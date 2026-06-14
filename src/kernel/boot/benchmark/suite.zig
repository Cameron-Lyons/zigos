const std = @import("std");
const x86 = @import("../../../arch/x86.zig");
const abi = @import("../../../native/core/abi.zig");
const console = @import("../../utils/console.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const benchmark_cases = @import("cases.zig");
const benchmark_authority = @import("authority.zig");
const benchmark_identities = @import("identities.zig");
const benchmark_reporting = @import("reporting.zig");
const boot_markers = @import("../markers.zig");
const capability = @import("../../../native/kernel_api/capability.zig");
const shared_memory = @import("../../../native/kernel_api/shared_memory.zig");
const crypto_hash = @import("../../../native/core/crypto_hash.zig");
const ids = @import("../../../native/core/ids.zig");
const principal = @import("../../../native/core/principal.zig");
const signing = @import("../../../native/core/signing.zig");
const units = @import("../../../native/core/units.zig");
const manifest = @import("../../../native/policy/manifest.zig");
const denial_explanation = @import("../../../native/policy/denial_explanation.zig");
const permission_review = @import("../../../native/policy/permission_review.zig");
const policy_mediation = @import("../../../native/policy/policy_mediation.zig");
const task_runtime = @import("../../../native/task/task_runtime.zig");
const background_dispatch = @import("../../../native/task/background_dispatch.zig");
const accelerator_scheduler = @import("../../../native/task/accelerator_scheduler.zig");
const userspace_executor = @import("../../../native/task/userspace_executor.zig");
const userspace_loader = @import("../../../native/task/userspace_loader.zig");
const userspace_scheduler = @import("../../../native/task/userspace_scheduler.zig");
const network_policy = @import("../../../native/sync/network_policy.zig");
const sync_service = @import("../../../native/sync/sync_service.zig");
const workspace = @import("../../../native/storage/workspace.zig");
const file_bridge = @import("../../../native/storage/file_bridge.zig");
const object_store = @import("../../../native/storage/object_store.zig");
const storage_service = @import("../../../native/storage/storage_service.zig");
const storage_volume = @import("../../../native/storage/storage_volume.zig");
const package_service = @import("../../../native/services/package_service.zig");
const package_service_bundle_ops = @import("../../../native/services/package_service_bundle_ops.zig");
const indexing_service = @import("../../../native/services/indexing_service.zig");
const notification_center = @import("../../../native/services/notification_center.zig");
const media_print_service = @import("../../../native/services/media_print_service.zig");
const compositor_session = @import("../../../native/platform/compositor_session.zig");
const event_ledger = @import("../../../native/platform/event_ledger.zig");
const immutable_base = @import("../../../native/platform/immutable_base.zig");
const recovery_environment = @import("../../../native/platform/recovery_environment.zig");
const secure_secret_store = @import("../../../native/platform/secure_secret_store.zig");
const update_health = @import("../../../native/platform/update_health.zig");
const driver_service = @import("../../../native/drivers/driver_service.zig");
const contract = @import("../../../native/session/contract.zig");
const supervisor_mod = @import("../../../native/session/supervisor.zig");

const kibibytes = units.kibibytes;
const mebibytes = units.mebibytes;
const app = benchmark_identities.app;
const device = benchmark_identities.device;
const policyAuthority = benchmark_identities.policyAuthority;
const service = benchmark_identities.service;
const signer = benchmark_identities.signer;
const user = benchmark_identities.user;
const benchmarkSyncAuthority = benchmark_authority.benchmarkSyncAuthority;
const mintBenchmarkSyncAuthority = benchmark_authority.mintBenchmarkSyncAuthority;
const mintDriverAuthority = benchmark_authority.mintDriverAuthority;
const zeroSyncAuthority = benchmark_authority.zeroSyncAuthority;

const PERMISSION_REVIEW_BENCH_BUFFER_BYTES: usize = kibibytes(2);
const EVENT_LEDGER_BENCH_BUFFER_BYTES: usize = kibibytes(2);
const DENIAL_EXPLANATION_BENCH_BUFFER_BYTES: usize = 192;
const CAPABILITY_REUSE_MINTED_IDS: usize = 128;
const FAIRNESS_BACKGROUND_TASKS: usize = 4;
const LATENCY_BACKGROUND_TASKS: usize = 4;
const UPDATE_HEALTH_CORE_SERVICE_COUNT: usize = 3;

const BenchmarkCase = benchmark_cases.BenchmarkCase;
const QualityGateCase = benchmark_cases.QualityGateCase;

const ScalingCapabilityTable = capability.CapabilityTableWith(.{
    .max_capabilities = 512,
    .capability_index_capacity = 1024,
    .max_target_generations = 128,
    .debug_index_checks = false,
});

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
    task_id: u64 = 0,
};

const WorkspaceCommitContext = struct {
    baseline: workspace.Directory = workspace.Directory.init(),
    workspace_id: ids.WorkspaceId = ids.WorkspaceId.zero,
};

const StorageVolumeContext = struct {
    volume: storage_volume.Volume = storage_volume.Volume.init(),
    seed_image: [storage_volume.image_bytes]u8 = [_]u8{0} ** storage_volume.image_bytes,
    store: object_store.Store = object_store.Store.init(),
    workspaces: workspace.Directory = workspace.Directory.init(),
    prepared: bool = false,
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
    signed_v1: manifest.BundleManifest = package_bundle_v1,
    signed_v2: manifest.BundleManifest = package_bundle_v2,
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
    capability_table: capability.CapabilityTable = capability.CapabilityTable.init(),
    authority: sync_service.AuthorityContext = zeroSyncAuthority(),
    workspace_id: u64 = 0,
    source_device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    target_device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
};

const RecoveryContext = struct {
    checkpoint_store: storage_service.CheckpointStore = .{},
    storage: storage_service.Service = undefined,
    manager: immutable_base.Manager = undefined,
    sync: sync_service.Service = undefined,
    sync_capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    sync_authority: sync_service.AuthorityContext = zeroSyncAuthority(),
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
    sync_capabilities: capability.CapabilityTable = capability.CapabilityTable.init(),
    compositor: compositor_session.Session = compositor_session.Session.init(),
    supervisor: supervisor_mod.Supervisor = supervisor_mod.Supervisor.init(),
    ledger: event_ledger.Ledger = event_ledger.Ledger.init(),
    core_service_ids: [UPDATE_HEALTH_CORE_SERVICE_COUNT]u64 = [_]u64{0} ** UPDATE_HEALTH_CORE_SERVICE_COUNT,
    request: update_health.CheckRequest = undefined,
};

const cases = benchmark_cases.benchmarkCases(.{
    .capability_derive = benchmarkCapabilityDerive,
    .capability_mint_reuse_free_slot = benchmarkCapabilityMintReuseFreeSlot,
    .capability_target_generation_lookup = benchmarkCapabilityTargetGenerationLookup,
    .permission_review_render = benchmarkPermissionReviewRender,
    .network_policy_authorize = benchmarkNetworkPolicyAuthorize,
    .background_dispatch = benchmarkBackgroundDispatch,
    .task_checkpoint_write_restore = benchmarkTaskCheckpointWriteRestore,
    .accelerator_claim_release = benchmarkAcceleratorClaimRelease,
    .file_bridge_resolve = benchmarkFileBridgeResolve,
    .workspace_commit_overlay = benchmarkWorkspaceCommitOverlay,
    .storage_volume_replay_segmented_log = benchmarkStorageVolumeReplaySegmentedLog,
    .storage_volume_compact_checkpoint = benchmarkStorageVolumeCompactCheckpoint,
    .package_revision = benchmarkPackageRevision,
    .indexing_query = benchmarkIndexingQuery,
    .media_print_submit_complete = benchmarkMediaPrintSubmitComplete,
    .event_ledger_export = benchmarkEventLedgerExport,
    .secret_store_import_handle_export = benchmarkSecretStoreImportHandleExport,
    .denial_explanation_render = benchmarkDenialExplanationRender,
    .overlay_session_flow = benchmarkOverlaySessionFlow,
    .recovery_lifecycle = benchmarkRecoveryLifecycle,
    .update_health_validation = benchmarkUpdateHealthValidation,
    .driver_recovery_restart = benchmarkDriverRecoveryRestart,
});

const quality_gates = benchmark_cases.qualityGateCases(.{
    .battery_saver_batch_delay = qualityBatterySaverBatchDelay,
    .thermal_critical_background_delay = qualityThermalCriticalBackgroundDelay,
    .memory_pressure_batch_delay = qualityMemoryPressureBatchDelay,
    .scheduler_fairness_ratio_percent = qualitySchedulerFairnessRatioPercent,
    .starvation_resistance_after_pressure = qualityStarvationResistanceAfterPressure,
    .background_throttling_delayed_dispatches = qualityBackgroundThrottlingDelayedDispatches,
    .latency_under_load_max_wait_ticks = qualityLatencyUnderLoadMaxWaitTicks,
});

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
            .memory_bytes = kibibytes(96),
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
        .egress_intent = .{
            .kind = .call_service,
            .service = "relay.notes.example",
        },
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

const package_signer_identity = signing.SignerIdentity{
    .label = "bench-package",
    .seed = signing.seedFromByte(0x45),
};

const package_policy_authority = principal.PrincipalId{ .kind = .policy_authority, .serial = 45 };
const package_publisher_principal = principal.PrincipalId{ .kind = .app, .serial = 45 };

var permission_review_buffer: [PERMISSION_REVIEW_BENCH_BUFFER_BYTES]u8 = undefined;
var permission_review_grants: [permission_review.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
var event_ledger_buffer: [EVENT_LEDGER_BENCH_BUFFER_BYTES]u8 = undefined;
var denial_explanation_buffer: [DENIAL_EXPLANATION_BENCH_BUFFER_BYTES]u8 = undefined;

var file_bridge_context = FileBridgeContext{};
var storage_volume_context = StorageVolumeContext{};
var permission_review_context = PermissionReviewContext{};
var network_policy_context = NetworkPolicyContext{};
var background_context = BackgroundContext{};
var workspace_commit_context = WorkspaceCommitContext{};
var task_checkpoint_context = TaskCheckpointContext{};
var package_context = PackageContext{};
var indexing_context = IndexingContext{};
var media_context = MediaContext{};
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
    const quality_cycles = runQualityGates();

    benchmark_reporting.emitSummary(cases.len, quality_gates.len, quality_cycles, total_cycles);
    console.print(boot_markers.bench_pass);
    console.print("\n");
    qemu_exit.success();
}

fn prepareFixtures() void {
    prepareFileBridgeFixture();
    preparePermissionReviewFixture();
    prepareNetworkPolicyFixture();
    prepareBackgroundFixture();
    prepareIndexingFixture();
    prepareOverlaySessionFixture();
    prepareWorkspaceCommitFixture();
    prepareTaskCheckpointFixture();
    preparePackageFixture();
}

fn prepareFileBridgeFixture() void {
    file_bridge_context.capability_table = capability.CapabilityTable.init();
    file_bridge_context.expected_workspace_id = 41;
    file_bridge_context.expected_path = "documents/plan.md";
    file_bridge_context.expected_version_id = 901;
    file_bridge_context.entry = workspace.Entry.init(
        file_bridge_context.expected_path,
        ids.object(900),
        ids.version(file_bridge_context.expected_version_id),
        .document,
    ) catch unreachable;
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
    const digest = crypto_hash.digestFromByte(0xAA);
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

fn prepareBackgroundFixture() void {
    background_context.runtime = task_runtime.Runtime.init();
    background_context.dispatcher = background_dispatch.Controller.init();

    const task = background_context.runtime.createTask(.{
        .owner = app(93),
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 10_000_000,
            .memory_bytes = mebibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = kibibytes(64),
            .background_allowed = true,
        },
        .ui_surface_id = 9,
        .local_only = false,
        .launch = .{
            .bundle_id = background_bundle.bundle_id,
        },
    }) catch unreachable;
    background_context.task_id = task.id;
}

fn prepareIndexingFixture() void {
    indexing_context.service = indexing_service.Service.init();
    indexing_context.service.upsert(1, 100, 1, "Alpha Notes", "alpha alpha roadmap") catch unreachable;
    indexing_context.service.upsert(1, 101, 2, "Quarterly Report", "finance alpha summary") catch unreachable;
    indexing_context.service.upsert(2, 200, 1, "Private Contract", "alpha restricted") catch unreachable;
}

fn prepareWorkspaceCommitFixture() void {
    workspace_commit_context.baseline = workspace.Directory.init();
    const notes = workspace_commit_context.baseline.create(.{
        .owner = app(41),
        .label = "benchmark-notes",
    }) catch unreachable;
    workspace_commit_context.workspace_id = notes.id;

    workspace_commit_context.baseline.beginTransaction(notes.id) catch unreachable;
    workspace_commit_context.baseline.stagePut(notes.id, "documents/plan.md", ids.object(900), ids.version(901), .document) catch unreachable;
    workspace_commit_context.baseline.stagePut(notes.id, "assets/cover.jpg", ids.object(902), ids.version(903), .media_asset) catch unreachable;
    workspace_commit_context.baseline.stagePut(notes.id, "collections/inbox", ids.object(904), ids.version(905), .collection) catch unreachable;
    _ = workspace_commit_context.baseline.commit(notes.id, 10) catch unreachable;
}

fn prepareStorageVolumeFixture() void {
    if (storage_volume_context.prepared) return;

    const owner = app(0xBEE0);
    const record = storage_volume_context.workspaces.create(.{
        .owner = owner,
        .label = "volume-bench",
    }) catch unreachable;
    const workspace_id = record.id;
    const save_count = @as(usize, storage_volume.replay_gate_segments) + 1;
    for (0..save_count) |index| {
        storage_volume_context.workspaces.beginTransaction(workspace_id) catch unreachable;
        storage_volume_context.workspaces.stagePut(
            workspace_id,
            "benchmarks/storage-volume.md",
            ids.object(0xBEE0),
            ids.version(900 + @as(u64, @intCast(index))),
            .document,
        ) catch unreachable;
        _ = storage_volume_context.workspaces.commit(workspace_id, 800 + @as(u64, @intCast(index))) catch unreachable;
        _ = storage_volume_context.volume.saveToImage(
            storage_volume_context.seed_image[0..],
            &storage_volume_context.store,
            &storage_volume_context.workspaces,
        ) catch unreachable;
    }

    storage_volume_context.prepared = true;
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
            .memory_bytes = mebibytes(2),
            .endpoint_slots = 8,
            .shared_memory_bytes = kibibytes(128),
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
            .memory_bytes = kibibytes(32),
            .shared_memory_bytes = kibibytes(4),
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
            .memory_bytes = kibibytes(128),
            .endpoint_slots = 4,
            .shared_memory_bytes = kibibytes(8),
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

fn preparePackageFixture() void {
    package_context.service = package_service.Service.init();
    package_context.signed_v1 = signedPackageBundle(package_bundle_v1);
    package_context.signed_v2 = signedPackageBundle(package_bundle_v2);
    trustBenchmarkPackagePublisher(&package_context.service);
    const slot = &package_context.service.slots[0];
    slot.in_use = true;
    package_service_bundle_ops.installNew(&slot.bundle, package_context.signed_v1, "store:zigos", 1, crypto_hash.digestFromByte(0x11)) catch unreachable;
    package_context.service.rebuildIndexes();
}

fn trustBenchmarkPackagePublisher(service_ref: *package_service.Service) void {
    _ = service_ref.trust_store.bindPolicyAuthorityRoot(
        package_policy_authority,
        signing.publicKeyFromByte(0x51),
    ) catch unreachable;
    _ = service_ref.trust_store.bindPublisher(
        package_publisher_principal,
        package_policy_authority,
        package_bundle_v1.publisher,
        signing.publicKey(package_signer_identity) catch unreachable,
    ) catch unreachable;
}

fn signedPackageBundle(template: manifest.BundleManifest) manifest.BundleManifest {
    var bundle = template;
    bundle.signature = signing.signWithDefaultRegistry(
        .ed25519,
        package_signer_identity,
        &package_service.digestBundle(bundle),
    ) catch unreachable;
    return bundle;
}

fn prepareOverlaySessionFixture() void {
    overlay_session_context.service = sync_service.Service.init(930, 71, service(33));
    overlay_session_context.capability_table = capability.CapabilityTable.init();
    const sync_authority_capability = mintBenchmarkSyncAuthority(
        &overlay_session_context.capability_table,
        &overlay_session_context.service,
    );
    overlay_session_context.authority = benchmarkSyncAuthority(
        &overlay_session_context.service,
        sync_authority_capability,
        10,
    );
    overlay_session_context.workspace_id = 4_200;
    overlay_session_context.source_device = device(191);
    overlay_session_context.target_device = device(192);

    var sync_port = sync_service.SyncPort.init(&overlay_session_context.service, &overlay_session_context.capability_table);
    const authority = overlay_session_context.authority;
    const owner = user(19);
    _ = sync_port.ensureUserRoot(authority, owner, "overlay-owner", signer("overlay-user", 0x61)) catch unreachable;
    _ = sync_port.enrollTrustedDevice(
        authority,
        owner,
        overlay_session_context.source_device,
        "overlay-laptop",
        signer("overlay-user", 0x61),
        signer("overlay-laptop", 0x62),
        10,
    ) catch unreachable;
    _ = sync_port.enrollTrustedDevice(
        authority,
        owner,
        overlay_session_context.target_device,
        "overlay-tablet",
        signer("overlay-user", 0x61),
        signer("overlay-tablet", 0x63),
        11,
    ) catch unreachable;

    const local_policy = sync_port.createNetworkPolicy(authority, .{
        .owner = overlay_session_context.service.owner,
        .workspace_id = overlay_session_context.workspace_id,
        .label = "overlay-local",
        .mode = .local_network,
    }) catch unreachable;
    const overlay_policy = sync_port.createNetworkPolicy(authority, .{
        .owner = overlay_session_context.service.owner,
        .workspace_id = overlay_session_context.workspace_id,
        .label = "overlay-service",
        .mode = .named_service_identity,
        .target = "overlay.workspace.sync",
    }) catch unreachable;
    const relay_policy = sync_port.createNetworkPolicy(authority, .{
        .owner = overlay_session_context.service.owner,
        .workspace_id = overlay_session_context.workspace_id,
        .label = "overlay-relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    }) catch unreachable;
    _ = sync_port.configureWorkspacePolicy(authority, .{
        .workspace_id = overlay_session_context.workspace_id,
        .owner = owner,
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.dev",
    }) catch unreachable;
    _ = sync_port.configureOverlay(
        authority,
        overlay_session_context.workspace_id,
        overlay_session_context.source_device,
        "overlay.workspace.sync",
        true,
    ) catch unreachable;
    _ = sync_port.publishPrivateService(
        authority,
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
    benchmark_reporting.emitResult(case.name, case.iterations, cycles, checksum);
    return cycles;
}

fn runQualityGates() u64 {
    var total_cycles: u64 = 0;
    inline for (quality_gates) |gate| {
        total_cycles +%= runQualityGate(gate);
    }
    benchmark_reporting.emitQualitySummary(quality_gates.len, total_cycles);
    return total_cycles;
}

fn runQualityGate(gate: QualityGateCase) u64 {
    const start = x86.rdtsc();
    const value = gate.run();
    const cycles = x86.rdtsc() - start;
    benchmark_reporting.emitQualityGate(gate.name, value, cycles);
    return cycles;
}

fn benchmarkCapabilityDerive(iteration: u32) u64 {
    var table = capability.CapabilityTable.init();
    const parent = table.mintBootRoot(.{
        .holder = app(10),
        .issuer = policyAuthority(1),
        .target = .{ .kind = .workspace, .id = 500 + iteration },
        .rights = .{ .workspace = .{
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
        .rights = .{ .workspace = .{ .object_read = true } },
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

fn benchmarkCapabilityMintReuseFreeSlot(iteration: u32) u64 {
    var table = ScalingCapabilityTable.init();
    var minted_ids: [CAPABILITY_REUSE_MINTED_IDS]u64 = [_]u64{0} ** CAPABILITY_REUSE_MINTED_IDS;
    var checksum: u64 = iteration;

    for (&minted_ids, 0..) |*capability_id, index| {
        const minted = table.mintBootRoot(.{
            .holder = app(1000 + @as(u32, @intCast(index % 31))),
            .issuer = policyAuthority(3),
            .target = .{ .kind = .workspace, .id = 8000 + iteration },
            .rights = .{ .workspace = .{
                .object_read = true,
                .object_write = true,
                .capability_query = true,
            } },
            .scope = .{
                .workspace_id = 8000 + iteration,
                .local_only = true,
            },
            .lease = .{
                .issued_at_ticks = 1,
                .expires_at_ticks = 1000,
            },
        }) catch unreachable;
        capability_id.* = minted.id;
        checksum +%= minted.id;
    }

    var index: usize = 0;
    while (index < minted_ids.len) : (index += 2) {
        table.revokeGrant(minted_ids[index]) catch unreachable;
    }

    index = 0;
    while (index < 64) : (index += 1) {
        const minted = table.mintBootRoot(.{
            .holder = app(2000 + @as(u32, @intCast(index % 31))),
            .issuer = policyAuthority(3),
            .target = .{ .kind = .workspace, .id = 8000 + iteration },
            .rights = .{ .workspace = .{
                .object_read = true,
                .capability_query = true,
            } },
            .scope = .{
                .workspace_id = 8000 + iteration,
                .local_only = true,
            },
            .lease = .{
                .issued_at_ticks = 1,
                .expires_at_ticks = 1000,
            },
        }) catch unreachable;
        checksum +%= minted.id + minted.holder.serial;
    }

    return checksum;
}

fn benchmarkCapabilityTargetGenerationLookup(iteration: u32) u64 {
    var table = ScalingCapabilityTable.init();
    var capabilities: [96]capability.Capability = undefined;
    var checksum: u64 = iteration;

    for (&capabilities, 0..) |*slot, index| {
        const target_id = 12_000 + iteration * 128 + @as(u32, @intCast(index));
        slot.* = table.mintBootRoot(.{
            .holder = app(3000 + @as(u32, @intCast(index % 31))),
            .issuer = policyAuthority(4),
            .target = .{ .kind = .service, .id = target_id },
            .rights = .{ .service = .{
                .capability_query = true,
                .capability_revoke = true,
            } },
            .scope = .{
                .task_id = 4000 + @as(u32, @intCast(index)),
                .local_only = true,
            },
            .lease = .{
                .issued_at_ticks = 1,
                .expires_at_ticks = 1000,
            },
        }) catch unreachable;
        checksum +%= slot.id;
    }

    for (capabilities, 0..) |capability_record, index| {
        if (table.isUsable(capability_record, 10)) checksum +%= @as(u64, @intCast(index + 1));
    }

    table.revokeTargetAuthority(capabilities[capabilities.len - 1].id) catch unreachable;
    if (!table.isUsable(capabilities[capabilities.len - 1], 10)) checksum +%= capabilities[capabilities.len - 1].target.id;
    return checksum;
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
    const decision = background_context.dispatcher.dispatch(
        &background_context.runtime,
        background_context.task_id,
        background_bundle,
        "sync",
        .sync_completion,
        40 + iteration,
    ) catch unreachable;
    _ = background_context.dispatcher.complete(&background_context.runtime, decision.record_id.?) catch unreachable;
    const task = background_context.runtime.find(background_context.task_id) orelse unreachable;
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
    const task_id = ids.task(800 + iteration);
    const object = shared.createWithAccess(task_id, kibibytes(64), .{
        .cpu = true,
        .gpu = true,
    }) catch unreachable;
    const claim = controller.claimWithSharedMemory(.{
        .task_id = task_id.raw(),
        .request = .{
            .class = .foreground_interactive,
            .wants_gpu = true,
            .shared_memory_bytes = object.size_bytes,
        },
        .shared_memory_object_id = object.id,
    }, &shared) catch unreachable;
    const released = controller.releaseClaim(claim.id, &shared) catch unreachable;
    return claim.id + object.id.raw() + @intFromBool(released) + @intFromEnum(claim.engine);
}

fn benchmarkFileBridgeResolve(iteration: u32) u64 {
    var bridge = file_bridge_context.bridge.?;
    const view = bridge.resolve(.{
        .workspace_id = file_bridge_context.expected_workspace_id,
        .path = "documents/plan.md",
        .access = .read,
    }, file_bridge_context.requester, file_bridge_context.authority_capability_id, 30 + iteration) catch unreachable;
    return view.object_id + view.version_id + view.path_len + @intFromBool(view.readable);
}

fn benchmarkWorkspaceCommitOverlay(iteration: u32) u64 {
    prepareWorkspaceCommitFixture();
    const directory = &workspace_commit_context.baseline;
    const workspace_id = workspace_commit_context.workspace_id;

    directory.beginTransaction(workspace_id) catch unreachable;
    directory.stagePut(workspace_id, "documents/plan.md", ids.object(900), ids.version(1_100 + iteration), .document) catch unreachable;
    directory.stageDelete(workspace_id, "assets/cover.jpg") catch unreachable;
    directory.stagePut(workspace_id, "documents/draft.md", ids.object(1_200 + iteration), ids.version(1_300 + iteration), .document) catch unreachable;
    directory.stagePut(workspace_id, "documents/tmp.md", ids.object(1_400 + iteration), ids.version(1_500 + iteration), .document) catch unreachable;
    directory.stageDelete(workspace_id, "documents/tmp.md") catch unreachable;

    const generation = directory.commit(workspace_id, 70 + iteration) catch unreachable;
    const entries = directory.entries(workspace_id) catch unreachable;
    const plan = directory.resolve(workspace_id, "documents/plan.md") catch unreachable;
    const draft = directory.resolve(workspace_id, "documents/draft.md") catch unreachable;
    return generation + entries.len + plan.version_id.raw() + draft.object_id.raw();
}

fn benchmarkStorageVolumeReplaySegmentedLog(iteration: u32) u64 {
    _ = iteration;
    prepareStorageVolumeFixture();

    const generation = storage_volume_context.volume.loadFromImage(
        storage_volume_context.seed_image[0..],
        &storage_volume_context.store,
        &storage_volume_context.workspaces,
    ) catch unreachable;
    const record = storage_volume_context.workspaces.findOwned(app(0xBEE0), "volume-bench") orelse unreachable;
    return generation + record.generation + record.entryCount();
}

fn benchmarkStorageVolumeCompactCheckpoint(iteration: u32) u64 {
    prepareStorageVolumeFixture();
    _ = storage_volume_context.volume.loadFromImage(
        storage_volume_context.seed_image[0..],
        &storage_volume_context.store,
        &storage_volume_context.workspaces,
    ) catch unreachable;
    const record = storage_volume_context.workspaces.findOwned(app(0xBEE0), "volume-bench") orelse unreachable;
    storage_volume_context.workspaces.beginTransaction(record.id) catch unreachable;
    storage_volume_context.workspaces.stagePut(
        record.id,
        "benchmarks/storage-volume.md",
        ids.object(0xBEE0),
        ids.version(10_000 + @as(u64, iteration)),
        .document,
    ) catch unreachable;
    _ = storage_volume_context.workspaces.commit(record.id, 10_000 + @as(u64, iteration)) catch unreachable;

    const before_compacted = storage_volume.testing.latestImageCompactedGeneration(storage_volume_context.seed_image[0..]) catch unreachable;
    const result = storage_volume_context.volume.saveToImage(
        storage_volume_context.seed_image[0..],
        &storage_volume_context.store,
        &storage_volume_context.workspaces,
    ) catch unreachable;
    const after_compacted = storage_volume.testing.latestImageCompactedGeneration(storage_volume_context.seed_image[0..]) catch unreachable;
    return result.generation + after_compacted - before_compacted + record.generation;
}

fn benchmarkPackageRevision(iteration: u32) u64 {
    _ = iteration;
    const slot = &package_context.service.slots[0];
    package_service_bundle_ops.installNew(&slot.bundle, package_context.signed_v1, "store:zigos", 1, crypto_hash.digestFromByte(0x11)) catch unreachable;
    package_service_bundle_ops.installRevision(
        &slot.bundle,
        package_context.signed_v2,
        "store:zigos",
        2,
        crypto_hash.digestFromByte(0x22),
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
    var sync_port = sync_service.SyncPort.init(&overlay_session_context.service, &overlay_session_context.capability_table);
    var authority = overlay_session_context.authority;
    const usage: sync_service.OverlaySessionUse = switch (@mod(iteration, 3)) {
        0 => .sync_replication,
        1 => .remote_access,
        else => .private_service,
    };
    const transport: sync_service.TransportMode = switch (usage) {
        .sync_replication => .device_to_device,
        .remote_access, .private_service => .relay_assisted,
    };
    authority.now_ticks = 40 + iteration;
    const session = sync_port.openOverlaySession(
        authority,
        overlay_session_context.workspace_id,
        overlay_session_context.source_device,
        overlay_session_context.target_device,
        usage,
        transport,
        if (usage == .private_service) "notes.remote" else null,
        40 + iteration,
    ) catch unreachable;
    authority.now_ticks = 41 + iteration;
    _ = sync_port.probeOverlaySession(authority, session.session_id, 41 + iteration) catch unreachable;
    const live = overlay_session_context.service.findOverlaySession(session.session_id) orelse unreachable;
    authority.now_ticks = 42 + iteration;
    _ = sync_port.closeOverlaySession(authority, session.session_id, 42 + iteration) catch unreachable;

    return session.session_id +
        session.overlay_id +
        live.keepalive_count +
        @as(u64, @intFromBool(session.encrypted)) +
        @as(u64, @intFromBool(session.relay_encrypted)) +
        @as(u64, @intFromBool(session.remote_access));
}

fn benchmarkRecoveryLifecycle(iteration: u32) u64 {
    prepareRecoveryFixture(iteration);
    const recovery_boot = recovery_context.environment.enterRecoveryBootProfile(.{
        .profile = .recovery,
        .requester = service(4),
        .actions = &.{
            .reinstall_base_image,
            .restore_workspace_snapshot,
            .repair_sync_metadata,
            .rotate_device_keys,
            .revoke_device_trust,
        },
    }, 16 + iteration) catch unreachable;
    const payload = if ((iteration & 1) == 0) "kernel=v2" else "kernel=v3";
    const reinstalled = recovery_context.environment.verifyAndReinstallImage(
        recovery_boot.session(),
        &recovery_context.manager,
        payload,
        signer("platform-image", 0x72),
        16 + iteration,
    ) catch unreachable;
    const restored = recovery_context.environment.restoreWorkspaceSnapshot(
        recovery_boot.session(),
        &recovery_context.storage,
        recovery_context.workspace_id,
        recovery_context.snapshot_id,
        17 + iteration,
    ) catch unreachable;
    const repaired = recovery_context.environment.repairSyncMetadata(
        recovery_boot.session(),
        &recovery_context.sync,
        &recovery_context.storage,
        recovery_context.workspace_id,
        recovery_context.tablet,
    ) catch unreachable;
    const rotation_generation = recovery_context.environment.rotateDeviceKeys(
        recovery_boot.session(),
        &recovery_context.sync,
        recovery_context.user,
        recovery_context.tablet,
        signer("platform-user", 0x74),
        signer("tablet-device-v2", 0x77),
        18 + iteration,
    ) catch unreachable;
    const revoked = recovery_context.environment.revokeDeviceTrust(
        recovery_boot.session(),
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
    const event = update_health_context.ledger.latestKindPtr(.update_transition) orelse unreachable;
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
            .format = manifest.SIGNATURE_FORMAT_ED25519,
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
        ledger.latestKindPtr(.driver_restart).?.sequence;
}

fn qualityBatterySaverBatchDelay() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_001, 701, 1, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = mebibytes(8),
        .battery_percent = 12,
        .battery_charging = false,
        .npu_driver_online = true,
    });

    const batch = createLoadTask(
        &runtime,
        701,
        .batch_compute,
        "quality-battery-batch",
        "app.quality.battery-batch",
        load_dispatch_cpu_tick_cost * 4,
        kibibytes(64),
        null,
    );
    if (!scheduler.registerTask(batch.id)) return 0;
    _ = scheduler.runNext(2);

    const stats = scheduler.taskDispatchStats(batch.id) orelse return 0;
    return @intFromBool(stats.dispatch_count == 0 and
        stats.delayed_dispatch_count >= 1 and
        stats.last_dispatch_reason == .battery_preserve);
}

fn qualityThermalCriticalBackgroundDelay() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_002, 702, 1, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = mebibytes(8),
        .thermal_milli_celsius = 92_000,
    });

    const background = createLoadTask(
        &runtime,
        702,
        .background_light,
        "quality-thermal-background",
        "app.quality.thermal-background",
        load_dispatch_cpu_tick_cost * 4,
        kibibytes(64),
        null,
    );
    if (!scheduler.registerTask(background.id)) return 0;
    _ = scheduler.runNext(2);

    const stats = scheduler.taskDispatchStats(background.id) orelse return 0;
    return @intFromBool(stats.dispatch_count == 0 and
        stats.delayed_dispatch_count >= 1 and
        stats.last_dispatch_reason == .thermal_throttle);
}

fn qualityMemoryPressureBatchDelay() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_003, 703, 1, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = kibibytes(32),
        .npu_driver_online = true,
    });

    const batch = createLoadTask(
        &runtime,
        703,
        .batch_compute,
        "quality-memory-batch",
        "app.quality.memory-batch",
        load_dispatch_cpu_tick_cost * 4,
        kibibytes(128),
        null,
    );
    if (!scheduler.registerTask(batch.id)) return 0;
    if (!scheduler.configureTaskDispatchRequest(batch.id, .{
        .class = .batch_compute,
        .wants_npu = true,
        .memory_bandwidth_units = 256,
        .shared_memory_bytes = kibibytes(64),
    }, false)) return 0;
    _ = scheduler.runNext(2);

    const stats = scheduler.taskDispatchStats(batch.id) orelse return 0;
    return @intFromBool(stats.dispatch_count == 0 and
        stats.delayed_dispatch_count >= 1 and
        stats.last_dispatch_reason == .memory_bandwidth);
}

fn qualitySchedulerFairnessRatioPercent() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_004, 704, 1, .{
        .total_cpu_budget_ticks = 1_000_000,
        .memory_capacity_bytes = mebibytes(16),
    });

    var task_ids: [FAIRNESS_BACKGROUND_TASKS]u64 = [_]u64{0} ** FAIRNESS_BACKGROUND_TASKS;
    for (&task_ids, 0..) |*task_id, index| {
        const task = createLoadTask(
            &runtime,
            710 + @as(u64, @intCast(index)),
            .background_light,
            "quality-fair-background",
            "app.quality.fair-background",
            load_dispatch_cpu_tick_cost * 128,
            kibibytes(64),
            null,
        );
        task_id.* = task.id;
        if (!scheduler.registerTask(task.id)) return std.math.maxInt(u64);
    }

    var round: u64 = 0;
    while (round < 64) : (round += 1) {
        _ = scheduler.runNext(10 + round);
    }

    var min_dispatches: u64 = std.math.maxInt(u64);
    var max_dispatches: u64 = 0;
    for (task_ids) |task_id| {
        const stats = scheduler.taskDispatchStats(task_id) orelse return std.math.maxInt(u64);
        min_dispatches = @min(min_dispatches, stats.dispatch_count);
        max_dispatches = @max(max_dispatches, stats.dispatch_count);
    }
    if (min_dispatches == 0) return std.math.maxInt(u64);
    return @divTrunc(max_dispatches * 100, min_dispatches);
}

fn qualityStarvationResistanceAfterPressure() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const background = createLoadTask(
        &runtime,
        730,
        .background_light,
        "quality-starve-background",
        "app.quality.starve-background",
        load_dispatch_cpu_tick_cost,
        kibibytes(64),
        null,
    );
    const batch = createLoadTask(
        &runtime,
        731,
        .batch_compute,
        "quality-starve-batch",
        "app.quality.starve-batch",
        load_dispatch_cpu_tick_cost,
        kibibytes(64),
        null,
    );
    if (!scheduler.registerTask(background.id)) return 0;
    if (!scheduler.registerTask(batch.id)) return 0;

    configureLoadTelemetry(&scheduler, 7_005, 705, 1, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = mebibytes(8),
        .thermal_milli_celsius = 92_000,
    });
    _ = scheduler.runNext(2);

    configureLoadTelemetry(&scheduler, 7_005, 705, 3, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = mebibytes(8),
    });
    _ = scheduler.runNext(4);
    _ = scheduler.runNext(5);

    const background_stats = scheduler.taskDispatchStats(background.id) orelse return 0;
    const batch_stats = scheduler.taskDispatchStats(batch.id) orelse return 0;
    if (background_stats.delayed_dispatch_count == 0 or batch_stats.delayed_dispatch_count == 0) return 0;
    return @min(background_stats.dispatch_count, batch_stats.dispatch_count);
}

fn qualityBackgroundThrottlingDelayedDispatches() u64 {
    var runtime = task_runtime.Runtime.init();
    const task = runtime.createTask(.{
        .owner = app(740),
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = mebibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = kibibytes(64),
            .background_allowed = true,
        },
        .local_only = false,
        .launch = .{
            .bundle_id = background_bundle.bundle_id,
        },
    }) catch unreachable;

    var dispatcher = background_dispatch.Controller.init();
    dispatcher.configure(.{
        .max_active_jobs = 2,
        .max_expected_duration_seconds = 300,
        .max_cpu_time_ticks = 2_000,
        .max_memory_bytes = kibibytes(128),
        .max_shared_memory_bytes = kibibytes(64),
    });

    const first = dispatcher.dispatch(&runtime, task.id, background_bundle, "sync", .sync_completion, 10) catch unreachable;
    const second = dispatcher.dispatch(&runtime, task.id, background_bundle, "sync", .sync_completion, 11) catch unreachable;
    const third = dispatcher.dispatch(&runtime, task.id, background_bundle, "sync", .sync_completion, 12) catch unreachable;
    return @intFromBool(first.allowed and
        second.allowed and
        third.delayed and
        third.reason == .throttled and
        dispatcher.activeRecordCount() == 2);
}

fn qualityLatencyUnderLoadMaxWaitTicks() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_006, 706, 1, .{
        .total_cpu_budget_ticks = 1_000_000,
        .memory_capacity_bytes = mebibytes(16),
    });

    var background_ids: [LATENCY_BACKGROUND_TASKS]u64 = [_]u64{0} ** LATENCY_BACKGROUND_TASKS;
    for (&background_ids, 0..) |*task_id, index| {
        const task = createLoadTask(
            &runtime,
            750 + @as(u64, @intCast(index)),
            .background_light,
            "quality-latency-background",
            "app.quality.latency-background",
            load_dispatch_cpu_tick_cost * 128,
            kibibytes(64),
            null,
        );
        task_id.* = task.id;
        if (!scheduler.registerTask(task.id)) return std.math.maxInt(u64);
    }

    const foreground = createLoadTask(
        &runtime,
        760,
        .foreground_interactive,
        "quality-latency-foreground",
        "app.quality.latency-foreground",
        load_dispatch_cpu_tick_cost * 32,
        kibibytes(64),
        9,
    );
    if (!scheduler.registerTask(foreground.id)) return std.math.maxInt(u64);
    if (!scheduler.parkTaskUntilEvent(foreground.id)) return std.math.maxInt(u64);

    var max_wait_ticks: u64 = 0;
    var tick: u64 = 20;
    var window: usize = 0;
    while (window < 8) : (window += 1) {
        var load_round: usize = 0;
        while (load_round < 3) : (load_round += 1) {
            _ = scheduler.runNext(tick);
            tick += 1;
        }

        if (!scheduler.wakeTask(foreground.id, .ipc_message, tick, tick + 5)) return std.math.maxInt(u64);
        _ = scheduler.runNext(tick + 1);
        const stats = scheduler.taskDispatchStats(foreground.id) orelse return std.math.maxInt(u64);
        if (stats.last_dispatch_tick < stats.last_wake_tick) return std.math.maxInt(u64);
        max_wait_ticks = @max(max_wait_ticks, stats.last_dispatch_tick - stats.last_wake_tick);
        if (!scheduler.parkTaskUntilEvent(foreground.id)) return std.math.maxInt(u64);
        tick += 2;
    }

    return max_wait_ticks;
}

const load_dispatch_cpu_tick_cost: u64 = 1_000;

fn configureLoadTelemetry(
    scheduler: *userspace_scheduler.Scheduler,
    boot_id: u64,
    task_id: u64,
    observed_tick: u64,
    counters: accelerator_scheduler.LivePlatformCounters,
) void {
    var provider = accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(
        boot_id,
        task_id,
        observed_tick,
        counters,
    ) catch unreachable;
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
}

fn createLoadTask(
    runtime: *task_runtime.Runtime,
    serial: u64,
    class: accelerator_scheduler.ResourceClass,
    label: []const u8,
    bundle_id: []const u8,
    cpu_ticks: u64,
    memory_bytes: usize,
    ui_surface_id: ?u64,
) *task_runtime.TaskRecord {
    var image = task_runtime.syntheticUserspaceImage(label, bundle_id);
    const service_task = class == .emergency_system_critical;
    return runtime.createTask(.{
        .owner = if (service_task) service(serial) else app(serial),
        .component_class = if (service_task) .service_component else .app_component,
        .budget = .{
            .cpu_time_ticks = cpu_ticks,
            .memory_bytes = memory_bytes,
            .endpoint_slots = 4,
            .shared_memory_bytes = kibibytes(64),
            .resource_class = class,
            .background_allowed = class == .background_light or class == .batch_compute,
        },
        .ui_surface_id = ui_surface_id,
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = serial,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = bundle_id,
        },
        .userspace_image = &image,
    }) catch unreachable;
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
        .preferred_object_id = ids.object(980),
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
        .preferred_object_id = ids.object(980),
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
    recovery_context.workspace_id = workspace_record.id.raw();
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
    recovery_context.snapshot_id = snapshot.id.raw();
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
    recovery_context.sync_capabilities = capability.CapabilityTable.init();
    const sync_authority_capability = mintBenchmarkSyncAuthority(
        &recovery_context.sync_capabilities,
        &recovery_context.sync,
    );
    recovery_context.sync_authority = benchmarkSyncAuthority(
        &recovery_context.sync,
        sync_authority_capability,
        16 + iteration,
    );
    var sync_port = sync_service.SyncPort.init(&recovery_context.sync, &recovery_context.sync_capabilities);
    const sync_authority = recovery_context.sync_authority;
    _ = sync_port.ensureUserRoot(sync_authority, recovery_context.user, "cameron", signer("platform-user", 0x74)) catch unreachable;
    _ = sync_port.enrollTrustedDevice(
        sync_authority,
        recovery_context.user,
        recovery_context.primary_device,
        "primary",
        signer("platform-user", 0x74),
        signer("primary-device", 0x75),
        16 + iteration,
    ) catch unreachable;
    _ = sync_port.enrollTrustedDevice(
        sync_authority,
        recovery_context.user,
        recovery_context.tablet,
        "tablet",
        signer("platform-user", 0x74),
        signer("tablet-device", 0x76),
        17 + iteration,
    ) catch unreachable;
    const local_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "local-net",
        .mode = .local_network,
    }) catch unreachable;
    _ = sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_record.id.raw(),
        .owner = recovery_context.user,
        .device_to_device_policy_id = local_policy.id,
        .selective_prefixes = &.{"documents/"},
    }) catch unreachable;
    sync_port.setReplicaVersion(
        sync_authority,
        workspace_record.id.raw(),
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
    update_health_context.sync_capabilities = capability.CapabilityTable.init();
    update_health_context.compositor = compositor_session.Session.init();
    update_health_context.supervisor = supervisor_mod.Supervisor.init();
    update_health_context.ledger = event_ledger.Ledger.init();

    const network_probe = seedUpdateHealthNetworkProbe(
        &update_health_context.sync,
        &update_health_context.sync_capabilities,
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
        .preferred_object_id = ids.object(7_700),
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
    return workspace_record.id.raw();
}

fn seedUpdateHealthNetworkProbe(
    sync: *sync_service.Service,
    capability_table: *capability.CapabilityTable,
    workspace_id: u64,
    tick_base: u64,
) update_health.NetworkProbe {
    const owner = user(88);
    const source_device = device(881);
    const target_device = device(882);
    const authority_capability = mintBenchmarkSyncAuthority(capability_table, sync);
    var port = sync_service.SyncPort.init(sync, capability_table);
    const authority = benchmarkSyncAuthority(sync, authority_capability, tick_base);
    _ = port.ensureUserRoot(authority, owner, "update-health", signer("update-health-user", 0x51)) catch unreachable;
    _ = port.enrollTrustedDevice(
        authority,
        owner,
        source_device,
        "source",
        signer("update-health-user", 0x51),
        signer("update-health-source", 0x52),
        tick_base,
    ) catch unreachable;
    _ = port.enrollTrustedDevice(
        authority,
        owner,
        target_device,
        "target",
        signer("update-health-user", 0x51),
        signer("update-health-target", 0x53),
        tick_base + 1,
    ) catch unreachable;

    const local_policy = port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "health-local",
        .mode = .local_network,
    }) catch unreachable;
    const overlay_policy = port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "health-overlay",
        .mode = .named_service_identity,
        .target = "overlay.health.sync",
    }) catch unreachable;
    _ = port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_id,
        .owner = owner,
        .device_to_device_policy_id = local_policy.id,
        .overlay_policy_id = overlay_policy.id,
    }) catch unreachable;
    _ = port.configureOverlay(authority, workspace_id, source_device, "overlay.health.sync", true) catch unreachable;

    return .{
        .sync = sync,
        .capability_table = capability_table,
        .authority = authority,
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
            .memory_bytes = kibibytes(64),
            .endpoint_slots = 2,
            .shared_memory_bytes = kibibytes(4),
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
