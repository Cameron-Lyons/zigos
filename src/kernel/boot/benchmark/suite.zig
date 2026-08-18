const std = @import("std");
const x86 = @import("../../../arch/x86.zig");
const abi = @import("../../../native/core/abi.zig");
const console = @import("../../utils/console.zig");
const gdt = @import("../../interrupts/gdt64.zig");
const isr = @import("../../interrupts/isr.zig");
const syscall64 = @import("../../interrupts/syscall64.zig");
const paging = @import("../../memory/paging64.zig");
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
const generated_image_fixtures = @import("../../../native/task/generated_image_fixtures.zig");
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
const CAPABILITY_LOOKUP_TARGET_COUNT: usize = 96;
const CAPABILITY_LOOKUP_LIVE_COUNT: usize = CAPABILITY_LOOKUP_TARGET_COUNT - 1;
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

const CapabilityLookupContext = struct {
    table: ScalingCapabilityTable = ScalingCapabilityTable.init(),
    live_capability_ids: [CAPABILITY_LOOKUP_LIVE_COUNT]u64 = [_]u64{0} ** CAPABILITY_LOOKUP_LIVE_COUNT,
    revoked_sibling_id: u64 = 0,
    revoked_target_id: u64 = 0,
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
    task_id: u64 = 0,
};

const SupervisorReadyContext = struct {
    supervisor: supervisor_mod.Supervisor = supervisor_mod.Supervisor.init(),
    service_id: u64 = 0,
};

const WorkspaceCommitContext = struct {
    baseline: workspace.Directory = workspace.Directory.init(),
    workspace_id: ids.WorkspaceId = ids.WorkspaceId.zero,
    current_cover_object_id: ids.ObjectId = ids.ObjectId.zero,
};

const StorageVolumeContext = struct {
    volume: storage_volume.Volume = storage_volume.Volume.init(),
    seed_image: [storage_volume.image_bytes]u8 = [_]u8{0} ** storage_volume.image_bytes,

    pristine_image: [storage_volume.image_bytes]u8 = [_]u8{0} ** storage_volume.image_bytes,
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

const BenchmarkImageContext = struct {
    prepared: bool = false,
    app_image: task_runtime.ExecutableImageSpec = .{},
    service_image: task_runtime.ExecutableImageSpec = .{},
};

const AddressSpaceBenchmarkContext = struct {
    prepared: bool = false,
    space: ?paging.UserAddressSpace = null,
};

const SyscallBenchmarkContext = struct {
    prepared: bool = false,
    handler_registered: bool = false,
    space: ?paging.UserAddressSpace = null,
    last_counter: u64 = 0,
};

const SYSCALL_BENCHMARK_CODE_ADDRESS: u32 = 0x4000_0000;
const SYSCALL_BENCHMARK_STACK_ADDRESS: u32 = 0xB000_0000;
const SYSCALL_BENCHMARK_PAGE_BYTES: u32 = 4096;
const SYSCALL_BENCHMARK_BATCH_SIZE: u64 = 64;

const SYSCALL_BENCHMARK_USER_FLAGS: u64 = userspace_executor.USER_RFLAGS_RESERVED;
const GENERAL_PROTECTION_FAULT_VECTOR: u8 = 13;
const USERSPACE_YIELD_VECTOR: u8 = 129;

extern const zigos_syscall_benchmark_user_start: u8;
extern const zigos_syscall_benchmark_user_end: u8;

const cases = benchmark_cases.benchmarkCases(.{
    .capability_derive = benchmarkCapabilityDerive,
    .capability_mint_reuse_free_slot = benchmarkCapabilityMintReuseFreeSlot,
    .capability_target_generation_lookup = benchmarkCapabilityTargetGenerationLookup,
    .permission_review_render = benchmarkPermissionReviewRender,
    .network_policy_authorize = benchmarkNetworkPolicyAuthorize,
    .background_dispatch = benchmarkBackgroundDispatch,
    .supervisor_ready_lookup = benchmarkSupervisorReadyLookup,
    .task_checkpoint_write_restore = benchmarkTaskCheckpointWriteRestore,
    .task_checkpoint_write_low_occupancy = benchmarkTaskCheckpointWriteLowOccupancy,
    .address_space_roundtrip = benchmarkAddressSpaceRoundtrip,
    .syscall_fast_entry_roundtrip = benchmarkSyscallFastEntryRoundtrip,
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
    .lower_class_service_debt_batch_tie_dispatch = qualityLowerClassServiceDebtBatchTieDispatch,
    .accelerator_claim_deadline_priority = qualityAcceleratorClaimDeadlinePriority,
    .brokered_accelerator_queue_completion_release = qualityBrokeredAcceleratorQueueCompletionRelease,
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
var supervisor_ready_context = SupervisorReadyContext{};
var workspace_commit_context = WorkspaceCommitContext{};
var task_checkpoint_context = TaskCheckpointContext{};
var package_context = PackageContext{};
var indexing_context = IndexingContext{};
var media_context = MediaContext{};
var event_ledger_context = EventLedgerContext{};
var secret_store_context = SecretStoreContext{};
var overlay_session_context = OverlaySessionContext{};
var capability_lookup_context = CapabilityLookupContext{};
var recovery_context = RecoveryContext{};
var update_health_context = UpdateHealthContext{};
var benchmark_image_context = BenchmarkImageContext{};
var address_space_benchmark_context = AddressSpaceBenchmarkContext{};
var syscall_benchmark_context = SyscallBenchmarkContext{};

var quality_gate_runtime: task_runtime.Runtime = task_runtime.Runtime.init();

pub fn run() noreturn {
    console.print("Running native spec-aligned benchmarks...\n");
    console.print(boot_markers.bench_start);
    console.print("\n");

    prepareBenchmarkUserspaceImages();

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
    prepareBenchmarkUserspaceImages();
    prepareAddressSpaceBenchmarkFixture();
    prepareSyscallBenchmarkFixture();
    prepareCapabilityLookupFixture();
    prepareFileBridgeFixture();
    preparePermissionReviewFixture();
    prepareNetworkPolicyFixture();
    prepareBackgroundFixture();
    prepareSupervisorReadyFixture();
    prepareIndexingFixture();
    prepareOverlaySessionFixture();
    prepareWorkspaceCommitFixture();
    prepareTaskCheckpointFixture();
    preparePackageFixture();
    restoreStorageVolumeSeedImage();
}

fn prepareAddressSpaceBenchmarkFixture() void {
    if (address_space_benchmark_context.prepared) return;
    address_space_benchmark_context.space = paging.createUserAddressSpace() catch |err|
        benchmark_reporting.benchStepFailure("address-space benchmark fixture", err);
    address_space_benchmark_context.prepared = true;
}

fn prepareSyscallBenchmarkFixture() void {
    if (syscall_benchmark_context.prepared) return;
    var space = paging.createUserAddressSpace() catch |err|
        benchmark_reporting.benchStepFailure("syscall benchmark address space", err);
    paging.mapOwnedUserRange(&space, SYSCALL_BENCHMARK_CODE_ADDRESS, SYSCALL_BENCHMARK_PAGE_BYTES, .{
        .writable = false,
        .executable = true,
    }) catch |err| benchmark_reporting.benchStepFailure("syscall benchmark code mapping", err);
    paging.mapOwnedUserRange(&space, SYSCALL_BENCHMARK_STACK_ADDRESS, SYSCALL_BENCHMARK_PAGE_BYTES, .{
        .writable = true,
    }) catch |err| benchmark_reporting.benchStepFailure("syscall benchmark stack mapping", err);

    const code_start = @intFromPtr(&zigos_syscall_benchmark_user_start);
    const code_end = @intFromPtr(&zigos_syscall_benchmark_user_end);
    if (code_end <= code_start or code_end - code_start > SYSCALL_BENCHMARK_PAGE_BYTES) {
        benchmark_reporting.benchStepFailure("syscall benchmark code extent", error.InvalidRange);
    }
    const code: [*]const u8 = @ptrFromInt(code_start);
    paging.writeOwnedUserRange(
        &space,
        SYSCALL_BENCHMARK_CODE_ADDRESS,
        code[0 .. code_end - code_start],
    ) catch |err| benchmark_reporting.benchStepFailure("syscall benchmark code copy", err);

    syscall_benchmark_context.space = space;
    if (!syscall_benchmark_context.handler_registered) {
        isr.registerHandler(GENERAL_PROTECTION_FAULT_VECTOR, syscallBenchmarkGeneralProtectionFault);
        isr.registerHandler(USERSPACE_YIELD_VECTOR, syscallBenchmarkYield);
        syscall_benchmark_context.handler_registered = true;
    }
    syscall_benchmark_context.prepared = true;
}

fn prepareCapabilityLookupFixture() void {
    capability_lookup_context = .{};
    var revoke_trigger_id: u64 = 0;

    for (0..CAPABILITY_LOOKUP_TARGET_COUNT) |index| {
        const target_id = 12_000 + @as(u64, @intCast(index));
        const minted = capability_lookup_context.table.mintBootRoot(.{
            .holder = app(3000 + @as(u32, @intCast(index % 31))),
            .issuer = policyAuthority(4),
            .target = .{ .kind = .service, .id = target_id },
            .rights = .{ .service = .{
                .capability_query = true,
                .capability_revoke = true,
            } },
            .scope = .{
                .task_id = 4000 + @as(u64, @intCast(index)),
                .local_only = true,
            },
            .lease = .{
                .issued_at_ticks = 1,
                .expires_at_ticks = 1000,
            },
        }) catch |err| benchmark_reporting.benchStepFailure("capability lookup fixture", err);
        if (index < CAPABILITY_LOOKUP_LIVE_COUNT) {
            capability_lookup_context.live_capability_ids[index] = minted.id;
        } else {
            revoke_trigger_id = minted.id;
            capability_lookup_context.revoked_target_id = target_id;
        }
    }

    const revoked_sibling = capability_lookup_context.table.mintBootRoot(.{
        .holder = app(3999),
        .issuer = policyAuthority(4),
        .target = .{ .kind = .service, .id = capability_lookup_context.revoked_target_id },
        .rights = .{ .service = .{
            .capability_query = true,
            .capability_revoke = true,
        } },
        .scope = .{
            .task_id = 4999,
            .local_only = true,
        },
        .lease = .{
            .issued_at_ticks = 1,
            .expires_at_ticks = 1000,
        },
    }) catch |err| benchmark_reporting.benchStepFailure("capability lookup fixture", err);
    capability_lookup_context.revoked_sibling_id = revoked_sibling.id;
    capability_lookup_context.table.revokeTargetAuthority(revoke_trigger_id) catch |err|
        benchmark_reporting.benchStepFailure("capability lookup fixture", err);
}

fn restoreStorageVolumeSeedImage() void {
    if (!storage_volume_context.prepared) return;
    @memcpy(storage_volume_context.seed_image[0..], storage_volume_context.pristine_image[0..]);
}

fn prepareBenchmarkUserspaceImages() void {
    if (benchmark_image_context.prepared) return;

    benchmark_image_context.app_image = generated_image_fixtures.appImage() catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    benchmark_image_context.service_image = generated_image_fixtures.serviceImage() catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    benchmark_image_context.prepared = true;
}

fn benchmarkAppImage() task_runtime.ExecutableImageSpec {
    prepareBenchmarkUserspaceImages();
    return benchmark_image_context.app_image;
}

fn benchmarkServiceImage() task_runtime.ExecutableImageSpec {
    prepareBenchmarkUserspaceImages();
    return benchmark_image_context.service_image;
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
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
            permission_review.parseCommand("allow local lease=200") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err),
        ),
        permission_review.decisionFromCommand(
            permission_review_requests[1],
            permission_review.parseCommand("allow lease=30") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err),
        ),
    };
}

fn prepareBackgroundFixture() void {
    background_context.runtime.reset();
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    background_context.task_id = task.id;
}

fn prepareSupervisorReadyFixture() void {
    supervisor_ready_context = .{};
    const service_record = supervisor_ready_context.supervisor.register(
        .network_stack,
        service(94),
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark supervisor readiness fixture", err);
    supervisor_ready_context.service_id = service_record.id;
    if (!supervisor_ready_context.supervisor.noteContractBound(service_record.id, 194, 1)) {
        benchmark_reporting.benchStepFailure("benchmark supervisor contract binding", error.ContractBindingFailed);
    }
    if (!supervisor_ready_context.supervisor.markHealthy(service_record.id, 2)) {
        benchmark_reporting.benchStepFailure("benchmark supervisor health", error.HealthTransitionFailed);
    }

    for (0..supervisor_mod.MAX_DIAGNOSTICS) |index| {
        if (!supervisor_ready_context.supervisor.markHealthy(
            service_record.id,
            3 + @as(u64, @intCast(index)),
        )) {
            benchmark_reporting.benchStepFailure("benchmark supervisor diagnostic rollover", error.HealthTransitionFailed);
        }
    }
}

fn prepareIndexingFixture() void {
    indexing_context.service = indexing_service.Service.init();
    indexing_context.service.upsert(1, 100, 1, "Alpha Notes", "alpha alpha roadmap") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    indexing_context.service.upsert(1, 101, 2, "Quarterly Report", "finance alpha summary") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    indexing_context.service.upsert(2, 200, 1, "Private Contract", "alpha restricted") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
}

fn prepareWorkspaceCommitFixture() void {
    workspace_commit_context.baseline = workspace.Directory.init();
    const notes = workspace_commit_context.baseline.create(.{
        .owner = app(41),
        .label = "benchmark-notes",
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    workspace_commit_context.workspace_id = notes.id;
    workspace_commit_context.current_cover_object_id = ids.object(902);

    workspace_commit_context.baseline.beginTransaction(notes.id) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    workspace_commit_context.baseline.stagePut(notes.id, "documents/plan.md", ids.object(900), ids.version(901), .document) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    workspace_commit_context.baseline.stagePut(notes.id, "assets/cover.jpg", ids.object(902), ids.version(903), .media_asset) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    workspace_commit_context.baseline.stagePut(notes.id, "collections/inbox", ids.object(904), ids.version(905), .collection) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = workspace_commit_context.baseline.commit(notes.id, 10) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
}

fn prepareStorageVolumeFixture() void {
    if (storage_volume_context.prepared) return;

    const owner = app(0xBEE0);
    const record = storage_volume_context.workspaces.create(.{
        .owner = owner,
        .label = "volume-bench",
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const workspace_id = record.id;
    const save_count = @as(usize, storage_volume.replay_gate_segments) + 1;
    for (0..save_count) |index| {
        storage_volume_context.workspaces.beginTransaction(workspace_id) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
        storage_volume_context.workspaces.stagePut(
            workspace_id,
            "benchmarks/storage-volume.md",
            ids.object(0xBEE0),
            ids.version(900 + @as(u64, @intCast(index))),
            .document,
        ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
        _ = storage_volume_context.workspaces.commit(workspace_id, 800 + @as(u64, @intCast(index))) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
        _ = storage_volume_context.volume.saveToImage(
            storage_volume_context.seed_image[0..],
            &storage_volume_context.store,
            &storage_volume_context.workspaces,
        ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    }

    @memcpy(storage_volume_context.pristine_image[0..], storage_volume_context.seed_image[0..]);
    storage_volume_context.prepared = true;
}

fn prepareTaskCheckpointFixture() void {
    task_checkpoint_context.source_runtime.reset();
    task_checkpoint_context.restored_runtime.reset();

    const sync_image = benchmarkAppImage();
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    task_checkpoint_context.primary_task_id = primary.id;
    _ = task_checkpoint_context.source_runtime.attachComponent(primary.id, .{
        .label = "sync-worker",
        .entry = "app.sync.worker",
    }, 60) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    task_checkpoint_context.source_runtime.grantCapability(primary.id, 301) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    task_checkpoint_context.source_runtime.grantCapability(primary.id, 302) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    task_checkpoint_context.source_runtime.audit(primary.id, .{
        .kind = .service_connected,
        .detail = 7,
        .tick = 62,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    task_checkpoint_context.secondary_task_id = helper.id;
    task_checkpoint_context.source_runtime.grantCapability(helper.id, 401) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    task_checkpoint_context.source_runtime.audit(helper.id, .{
        .kind = .policy_allowed,
        .detail = 1,
        .tick = 63,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
}

fn preparePackageFixture() void {
    package_context.service.reset();
    package_context.signed_v1 = signedPackageBundle(package_bundle_v1);
    package_context.signed_v2 = signedPackageBundle(package_bundle_v2);
    trustBenchmarkPackagePublisher(&package_context.service);
    _ = package_context.service.install(.{
        .bundle = package_context.signed_v1,
        .source_identity = "benchmark:zigos",
    }, null) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
}

fn trustBenchmarkPackagePublisher(service_ref: *package_service.Service) void {
    _ = service_ref.trust_store.bindPolicyAuthorityRoot(
        package_policy_authority,
        signing.publicKeyFromByte(0x51),
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = service_ref.trust_store.bindPublisher(
        package_publisher_principal,
        package_policy_authority,
        package_bundle_v1.publisher,
        signing.publicKey(package_signer_identity) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err),
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
}

fn signedPackageBundle(template: manifest.BundleManifest) manifest.BundleManifest {
    var bundle = template;
    bundle.signature = signing.signWithDefaultRegistry(
        .ed25519,
        package_signer_identity,
        &package_service.digestBundle(bundle),
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    _ = sync_port.ensureUserRoot(authority, owner, "overlay-owner", signer("overlay-user", 0x61)) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = sync_port.enrollTrustedDevice(
        authority,
        owner,
        overlay_session_context.source_device,
        "overlay-laptop",
        signer("overlay-user", 0x61),
        signer("overlay-laptop", 0x62),
        10,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = sync_port.enrollTrustedDevice(
        authority,
        owner,
        overlay_session_context.target_device,
        "overlay-tablet",
        signer("overlay-user", 0x61),
        signer("overlay-tablet", 0x63),
        11,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

    const local_policy = sync_port.createNetworkPolicy(authority, .{
        .owner = overlay_session_context.service.owner,
        .workspace_id = overlay_session_context.workspace_id,
        .label = "overlay-local",
        .mode = .local_network,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const overlay_policy = sync_port.createNetworkPolicy(authority, .{
        .owner = overlay_session_context.service.owner,
        .workspace_id = overlay_session_context.workspace_id,
        .label = "overlay-service",
        .mode = .named_service_identity,
        .target = "overlay.workspace.sync",
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const relay_policy = sync_port.createNetworkPolicy(authority, .{
        .owner = overlay_session_context.service.owner,
        .workspace_id = overlay_session_context.workspace_id,
        .label = "overlay-relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = sync_port.configureWorkspacePolicy(authority, .{
        .workspace_id = overlay_session_context.workspace_id,
        .owner = owner,
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.zigos.dev",
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = sync_port.configureOverlay(
        authority,
        overlay_session_context.workspace_id,
        overlay_session_context.source_device,
        "overlay.workspace.sync",
        true,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = sync_port.publishPrivateService(
        authority,
        overlay_session_context.workspace_id,
        "notes.remote",
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
}

const BENCH_MEASUREMENT_PASSES: u32 = 3;

fn runCase(case: BenchmarkCase) u64 {
    if (case.operations_per_iteration == 0 or case.iterations % case.operations_per_iteration != 0) {
        benchmark_reporting.benchStepFailure("benchmark operation batching", error.InvalidRange);
    }
    const measurement_iterations = case.iterations / case.operations_per_iteration;
    var best_cycles: u64 = std.math.maxInt(u64);
    var best_checksum: u64 = 0;
    var pass: u32 = 0;
    while (pass < BENCH_MEASUREMENT_PASSES) : (pass += 1) {
        prepareFixtures();
        var checksum: u64 = 0;
        const start = x86.rdtsc();
        var iteration: u32 = 0;
        while (iteration < measurement_iterations) : (iteration += 1) {
            checksum +%= case.runIteration(iteration);
        }
        const cycles = x86.rdtsc() - start;
        if (cycles < best_cycles) {
            best_cycles = cycles;
            best_checksum = checksum;
        }
    }
    benchmark_reporting.emitResult(case.name, case.iterations, best_cycles, best_checksum);
    return best_cycles;
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
        }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
        capability_id.* = minted.id;
        checksum +%= minted.id;
    }

    var index: usize = 0;
    while (index < minted_ids.len) : (index += 2) {
        table.revokeGrant(minted_ids[index]) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
        }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
        checksum +%= minted.id + minted.holder.serial;
    }

    return checksum;
}

fn benchmarkCapabilityTargetGenerationLookup(iteration: u32) u64 {
    const live_index = @as(usize, @intCast(iteration)) % CAPABILITY_LOOKUP_LIVE_COUNT;
    const live = capability_lookup_context.table.requireUsable(capability_lookup_context.live_capability_ids[live_index], 10) catch |err|
        benchmark_reporting.benchStepFailure("benchmark live capability lookup", err);
    const sibling_state = capability_lookup_context.table.inspect(capability_lookup_context.revoked_sibling_id, 10) orelse
        benchmark_reporting.benchStepFailure("benchmark target-generation sibling lookup", error.CapabilityNotFound);
    if (sibling_state.usable) benchmark_reporting.benchStepFailure("benchmark target-generation revocation", error.CapabilityRevoked);
    return live.id + live.target.id + sibling_state.capability.id + capability_lookup_context.revoked_target_id + iteration;
}

fn benchmarkPermissionReviewRender(iteration: u32) u64 {
    const session = permission_review.initSession(
        200 + iteration,
        &permission_review_bundle,
        permission_review_context.decisions[0..],
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const rendered = permission_review.renderToBuffer(
        &permission_review_buffer,
        &session,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    std.mem.doNotOptimizeAway(&permission_review_buffer);
    const grants = permission_review.decisionsToGrants(
        &session,
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
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = background_context.dispatcher.complete(&background_context.runtime, .{
        .record_id = decision.record_id.?,
        .expected_task_id = background_context.task_id,
        .expected_background_task_id = "sync",
        .expected_trigger = .sync_completion,
        .tick = 45 + iteration,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const task = background_context.runtime.find(background_context.task_id) orelse unreachable;
    return @intFromBool(decision.allowed) +
        decision.expected_duration_seconds +
        task.background_cpu_consumed_ticks +
        @intFromEnum(task.last_background_network);
}

fn benchmarkSupervisorReadyLookup(iteration: u32) u64 {
    if (!supervisor_ready_context.supervisor.isReady(supervisor_ready_context.service_id)) {
        benchmark_reporting.benchStepFailure("benchmark supervisor readiness", error.ServiceNotReady);
    }
    return supervisor_ready_context.service_id + iteration;
}

fn benchmarkTaskCheckpointWriteRestore(iteration: u32) u64 {
    _ = iteration;
    task_checkpoint_context.source_runtime.writeSnapshot(&task_checkpoint_context.snapshot);
    task_checkpoint_context.restored_runtime.restoreFromSnapshot(&task_checkpoint_context.snapshot) catch |err|
        benchmark_reporting.benchStepFailure("benchmark task checkpoint restore", err);

    const restored_primary = task_checkpoint_context.restored_runtime.find(task_checkpoint_context.primary_task_id) orelse unreachable;
    const restored_helper = task_checkpoint_context.restored_runtime.find(task_checkpoint_context.secondary_task_id) orelse unreachable;
    const restored_address_space = task_checkpoint_context.restored_runtime.findAddressSpaceConst(restored_primary.address_space_id) orelse unreachable;
    const latest_primary = restored_primary.latestAuditEvent() orelse unreachable;
    const latest_helper = restored_helper.latestAuditEvent() orelse unreachable;

    return restored_primary.id +
        restored_primary.execution_component_count +
        restored_primary.capability_count +
        restored_address_space.load_segment_count +
        restored_primary.background_cpu_consumed_ticks +
        latest_primary.tick +
        restored_helper.capability_count +
        latest_helper.tick;
}

fn benchmarkTaskCheckpointWriteLowOccupancy(iteration: u32) u64 {
    _ = iteration;

    task_checkpoint_context.source_runtime.writeSnapshot(&task_checkpoint_context.snapshot);
    std.mem.doNotOptimizeAway(&task_checkpoint_context.snapshot);

    const primary = &task_checkpoint_context.snapshot.tasks[0].task;
    const helper = &task_checkpoint_context.snapshot.tasks[1].task;
    return task_checkpoint_context.snapshot.next_task_id +
        task_checkpoint_context.snapshot.task_count +
        task_checkpoint_context.snapshot.address_space_count +
        primary.id +
        primary.address_space_id +
        primary.execution_component_count +
        primary.capability_count +
        primary.latestAuditEvent().?.tick +
        helper.id +
        helper.address_space_id +
        helper.capability_count +
        helper.latestAuditEvent().?.tick;
}

fn benchmarkAddressSpaceRoundtrip(iteration: u32) u64 {
    const space = &address_space_benchmark_context.space.?;
    paging.switchToUserAddressSpace(space);
    paging.switchToKernelAddressSpace();
    return @as(u64, iteration) ^ @as(u64, @intFromPtr(paging.getCurrentPageDirectory()));
}

fn benchmarkSyscallFastEntryRoundtrip(iteration: u32) u64 {
    const space = &syscall_benchmark_context.space.?;
    const kernel_stack_top = userspace_executor.prepareKernelStack();
    gdt.setKernelStack(kernel_stack_top);
    syscall64.setKernelStack(kernel_stack_top);
    userspace_executor.zigos_userspace_resume_requested = 0;
    syscall_benchmark_context.last_counter = 0;

    var context = userspace_executor.UserContext64{
        .r12 = SYSCALL_BENCHMARK_BATCH_SIZE,
        .r13 = iteration + 1,
        .instruction_pointer = SYSCALL_BENCHMARK_CODE_ADDRESS,
        .flags = SYSCALL_BENCHMARK_USER_FLAGS,
        .stack_pointer = SYSCALL_BENCHMARK_STACK_ADDRESS + SYSCALL_BENCHMARK_PAGE_BYTES - 16,
    };
    paging.switchToUserAddressSpace(space);
    _ = userspace_executor.enterPreparedUserContext(&context);
    if (paging.getCurrentPageDirectory() == space.directory) {
        paging.switchToKernelAddressSpace();
    }
    userspace_executor.zigos_userspace_resume_requested = 0;
    return syscall_benchmark_context.last_counter;
}

fn syscallBenchmarkYield(frame: *isr.InterruptFrame) void {
    syscall_benchmark_context.last_counter = frame.eax;
    userspace_executor.zigos_userspace_resume_requested = 1;
    paging.switchToKernelAddressSpace();
}

fn syscallBenchmarkGeneralProtectionFault(frame: *isr.InterruptFrame) void {
    var line_buffer: [192]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buffer,
        "BENCH:FAIL:syscall.fast_entry_roundtrip:general-protection:eip=0x{x}:cs=0x{x}:error=0x{x}\n",
        .{ frame.eip, frame.cs, frame.err_code },
    ) catch "BENCH:FAIL:syscall.fast_entry_roundtrip:general-protection:format-error\n";
    console.print(line);
    qemu_exit.failure();
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
    defer shared.deinit();
    const task_id = ids.task(800 + iteration);
    const object = shared.createWithAccess(task_id, kibibytes(64), .{
        .cpu = true,
        .gpu = true,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const claim = controller.claimWithSharedMemory(.{
        .task_id = task_id.raw(),
        .request = .{
            .class = .foreground_interactive,
            .wants_gpu = true,
            .shared_memory_bytes = object.size_bytes,
        },
        .shared_memory_object_id = object.id,
    }, &shared) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    std.mem.doNotOptimizeAway(&controller);
    std.mem.doNotOptimizeAway(&shared);
    const released = controller.releaseClaim(claim.id, &shared) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    std.mem.doNotOptimizeAway(&controller);
    std.mem.doNotOptimizeAway(&shared);
    return claim.id + object.id.raw() + @intFromBool(released) + @intFromEnum(claim.engine);
}

fn benchmarkFileBridgeResolve(iteration: u32) u64 {
    var bridge = file_bridge_context.bridge.?;
    const path = "documents/plan.md";
    const view = bridge.resolve(.{
        .workspace_id = file_bridge_context.expected_workspace_id,
        .path = path,
        .access = .read,
    }, file_bridge_context.requester, file_bridge_context.authority_capability_id, 30 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    return view.object_id + view.version_id + path.len + @intFromBool(view.readable);
}

fn benchmarkWorkspaceCommitOverlay(iteration: u32) align(4096) u64 {
    const directory = &workspace_commit_context.baseline;
    const workspace_id = workspace_commit_context.workspace_id;
    var next_cover_object_id = workspace_commit_context.current_cover_object_id;

    directory.beginTransaction(workspace_id) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    if ((iteration & 1) == 0) {
        directory.stagePut(workspace_id, "documents/plan.md", ids.object(900), ids.version(1_100 + iteration), .document) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    } else {
        next_cover_object_id = ids.object(1_200 + iteration);
        directory.stagePut(workspace_id, "assets/cover.jpg", next_cover_object_id, ids.version(1_300 + iteration), .media_asset) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    }

    const generation = directory.commit(workspace_id, 70 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    workspace_commit_context.current_cover_object_id = next_cover_object_id;
    const plan = directory.resolve(workspace_id, "documents/plan.md") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const cover = directory.resolve(workspace_id, "assets/cover.jpg") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const cover_by_object = directory.resolveObject(workspace_id, workspace_commit_context.current_cover_object_id) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const root_address = directory.find(workspace_id).?.rootAddress();

    var checksum = generation + plan.version_id.raw() + cover.object_id.raw() + cover_by_object.version_id.raw();
    var root_word_offset: usize = 0;
    while (root_word_offset < root_address.len) : (root_word_offset += @sizeOf(u64)) {
        checksum +%= std.mem.readInt(u64, root_address[root_word_offset..][0..@sizeOf(u64)], .little);
    }
    return checksum;
}

fn benchmarkStorageVolumeReplaySegmentedLog(iteration: u32) u64 {
    _ = iteration;
    prepareStorageVolumeFixture();

    const generation = storage_volume_context.volume.loadFromImage(
        storage_volume_context.seed_image[0..],
        &storage_volume_context.store,
        &storage_volume_context.workspaces,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const record = storage_volume_context.workspaces.findOwned(app(0xBEE0), "volume-bench") orelse unreachable;
    return generation + record.generation + record.entryCount();
}

fn benchmarkStorageVolumeCompactCheckpoint(iteration: u32) u64 {
    prepareStorageVolumeFixture();
    _ = storage_volume_context.volume.loadFromImage(
        storage_volume_context.seed_image[0..],
        &storage_volume_context.store,
        &storage_volume_context.workspaces,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const record = storage_volume_context.workspaces.findOwned(app(0xBEE0), "volume-bench") orelse unreachable;
    storage_volume_context.workspaces.beginTransaction(record.id) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    storage_volume_context.workspaces.stagePut(
        record.id,
        "benchmarks/storage-volume.md",
        ids.object(0xBEE0),
        ids.version(10_000 + @as(u64, iteration)),
        .document,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = storage_volume_context.workspaces.commit(record.id, 10_000 + @as(u64, iteration)) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

    const before_compacted = storage_volume.testing.latestImageCompactedGeneration(storage_volume_context.seed_image[0..]) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const result = storage_volume_context.volume.saveToImage(
        storage_volume_context.seed_image[0..],
        &storage_volume_context.store,
        &storage_volume_context.workspaces,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const after_compacted = storage_volume.testing.latestImageCompactedGeneration(storage_volume_context.seed_image[0..]) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    return result.generation + after_compacted - before_compacted + record.generation;
}

fn benchmarkPackageRevision(iteration: u32) u64 {
    _ = iteration;
    const bundle = package_context.service.find("app.notes") orelse benchmark_reporting.benchStepFailure("benchmark suite", error.BundleNotFound);
    package_service_bundle_ops.installNew(bundle, package_context.signed_v1, "benchmark:zigos", 1, crypto_hash.digestFromByte(0x11)) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    package_service_bundle_ops.installRevision(
        bundle,
        package_context.signed_v2,
        "benchmark:zigos",
        2,
        crypto_hash.digestFromByte(0x22),
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const active = package_service_bundle_ops.resolveActiveManifest(bundle, &package_context.resolved);
    const launch_plan = package_context.service.buildLaunchPlan("app.notes") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    package_service_bundle_ops.rollback(bundle);
    return active.version_minor +
        launch_plan.components.len +
        launch_plan.assets.len +
        bundle.activeRevision().version_minor +
        @intFromBool(bundle.rollbackAvailable());
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
    }, &media_context.scheduler, &media_context.notifications, 20 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const print_job = media_context.service.submit(.{
        .kind = .print_document,
        .task_id = 502 + iteration,
        .workspace_id = 11,
        .source_principal = source,
        .label = "print itinerary",
        .printer_identity = "printer://lobby",
        .visibility = .user,
    }, &media_context.scheduler, &media_context.notifications, 21 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

    _ = media_context.service.complete(print_job.id, &media_context.scheduler, &media_context.notifications, 30 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = media_context.service.complete(export_job.id, &media_context.scheduler, &media_context.notifications, 31 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    std.mem.doNotOptimizeAway(&media_context.service);

    return export_job.id +
        print_job.id +
        @intFromEnum(export_job.engine) +
        media_context.notifications.activeCount(31 + iteration);
}

fn benchmarkEventLedgerExport(iteration: u32) u64 {
    event_ledger_context.ledger.reset();
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
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    event_ledger_context.ledger.recordProcessCrash(.network_stack, service_subject, 21 + iteration, 5001, "segfault") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    event_ledger_context.ledger.recordDriverRestart(.media_print_helpers, service_subject, 88 + iteration, 22 + iteration, "audio-print restarted") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    event_ledger_context.ledger.recordUpdateTransition(service_subject, 1, .boot, true, 23 + iteration, "rolled back to stable-a") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    event_ledger_context.ledger.recordSyncConflict(user_subject, 5, 24 + iteration, "documents/tax-return.pdf conflict", true) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    event_ledger_context.ledger.recordDeviceTrustChange(user_subject, device_subject, false, 25 + iteration, "device revoked") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

    const exported = event_ledger_context.ledger.exportText(&event_ledger_buffer, .{}) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    return exported.len + event_ledger_context.ledger.next_sequence;
}

fn benchmarkSecretStoreImportHandleExport(iteration: u32) u64 {
    secret_store_context.store = secure_secret_store.Store.init();
    secret_store_context.store.attachHardwareProvider(.{ .available = true });
    const exportable = (iteration & 1) != 0;
    const secret = secret_store_context.store.importSecret(
        secret_store_context.owner,
        if (exportable) "backup-code" else "api-key",
        if (exportable) "abcd-efgh" else "super-secret-token",
        !exportable,
        exportable,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const handle = secret_store_context.store.lendHandle(
        secret.id,
        secret_store_context.holder,
        700 + iteration,
        true,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const described = secret_store_context.store.describeHandle(handle.id) orelse unreachable;
    if (exportable) {
        const exported = secret_store_context.store.exportRaw(handle.id, .{
            .holder = secret_store_context.holder,
            .task_id = 700 + iteration,
        }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
        return secret.id +
            handle.id +
            described.task_id +
            exported.len +
            @as(u64, @intFromBool(described.export_allowed));
    }
    _ = secret_store_context.store.exportRaw(handle.id, .{
        .holder = secret_store_context.holder,
        .task_id = 700 + iteration,
    }) catch |err| switch (err) {
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
    const rendered = denial_explanation.renderToBuffer(&denial_explanation_buffer, explanation) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    std.mem.doNotOptimizeAway(&denial_explanation_buffer);
    return rendered.len +
        explanation.policySlice().len +
        explanation.missingCapabilitySlice().len +
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
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    authority.now_ticks = 41 + iteration;
    _ = sync_port.probeOverlaySession(authority, session.session_id, 41 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const live = overlay_session_context.service.findOverlaySession(session.session_id) orelse unreachable;
    authority.now_ticks = 42 + iteration;
    _ = sync_port.closeOverlaySession(authority, session.session_id, 42 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

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
    }, 16 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const payload = if ((iteration & 1) == 0) "kernel=v2" else "kernel=v3";
    const reinstalled = recovery_context.environment.verifyAndReinstallImage(
        recovery_boot.session(),
        &recovery_context.manager,
        payload,
        signer("platform-image", 0x72),
        16 + iteration,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const restored = recovery_context.environment.restoreWorkspaceSnapshot(
        recovery_boot.session(),
        &recovery_context.storage,
        recovery_context.workspace_id,
        recovery_context.snapshot_id,
        17 + iteration,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const repaired = recovery_context.environment.repairSyncMetadata(
        recovery_boot.session(),
        &recovery_context.sync,
        &recovery_context.storage,
        recovery_context.workspace_id,
        recovery_context.tablet,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const rotation_generation = recovery_context.environment.rotateDeviceKeys(
        recovery_boot.session(),
        &recovery_context.sync,
        recovery_context.user,
        recovery_context.tablet,
        signer("platform-user", 0x74),
        signer("tablet-device-v2", 0x77),
        18 + iteration,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const revoked = recovery_context.environment.revokeDeviceTrust(
        recovery_boot.session(),
        &recovery_context.sync,
        recovery_context.user,
        recovery_context.tablet,
        signer("platform-user", 0x74),
        19 + iteration,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

    return @as(u64, @intFromBool(reinstalled)) +
        @as(u64, @intFromBool(restored)) +
        @as(u64, @intFromBool(repaired)) +
        rotation_generation +
        @as(u64, @intFromBool(revoked)) +
        @as(u64, @intFromBool(recovery_context.environment.report.image_activated));
}

fn benchmarkUpdateHealthValidation(iteration: u32) u64 {
    prepareUpdateHealthFixture(iteration);
    update_health_context.manager.beginActivation(0, 13 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    update_health.recordBootSuccess(&update_health_context.manager, 14 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const result = update_health.validatePendingActivation(
        &update_health_context.manager,
        &update_health_context.supervisor,
        &update_health_context.storage,
        update_health_context.request,
        &update_health_context.ledger,
        15 + iteration,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    const compositor = supervisor.register(.compositor_ui_session, service(50 + iteration)) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
            .format = .ed25519,
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

    var runtime = DriverRecoveryRuntime{};
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    defer ledger.deinit();
    const recovery = supervisor.recoverDriverCrash(
        compositor.id,
        &directory,
        &runtime,
        &notifications,
        &ledger,
        10 + iteration,
        0xD1,
        "display driver restart",
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

    return driver.restart_generation +
        runtime.activation_count +
        compositor.restart_count +
        @as(u64, @intFromBool(recovery.visible_impact)) +
        @as(u64, @intFromBool(recovery.notification_id != null)) +
        ledger.latestKind(.driver_restart).?.sequence;
}

fn qualityBatterySaverBatchDelay() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    defer scheduler.deinit();
    var catalog = userspace_loader.Catalog.init();
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_001, 701, 1, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = mebibytes(8),
        .battery_percent = 12,
        .battery_charging = false,
        .npu_driver_online = true,
    });

    const batch = createLoadTask(
        runtime,
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
    defer scheduler.deinit();
    var catalog = userspace_loader.Catalog.init();
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_002, 702, 1, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = mebibytes(8),
        .thermal_milli_celsius = 92_000,
    });

    const background = createLoadTask(
        runtime,
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
    defer scheduler.deinit();
    var catalog = userspace_loader.Catalog.init();
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_003, 703, 1, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = kibibytes(32),
        .npu_driver_online = true,
    });

    const batch = createLoadTask(
        runtime,
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
    defer scheduler.deinit();
    var catalog = userspace_loader.Catalog.init();
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_004, 704, 1, .{
        .total_cpu_budget_ticks = 1_000_000,
        .memory_capacity_bytes = mebibytes(16),
    });

    var task_ids: [FAIRNESS_BACKGROUND_TASKS]u64 = [_]u64{0} ** FAIRNESS_BACKGROUND_TASKS;
    for (&task_ids, 0..) |*task_id, index| {
        const task = createLoadTask(
            runtime,
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
    defer scheduler.deinit();
    var catalog = userspace_loader.Catalog.init();
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, runtime, &capabilities);

    const background = createLoadTask(
        runtime,
        730,
        .background_light,
        "quality-starve-background",
        "app.quality.starve-background",
        load_dispatch_cpu_tick_cost,
        kibibytes(64),
        null,
    );
    const batch = createLoadTask(
        runtime,
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

fn qualityLowerClassServiceDebtBatchTieDispatch() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    defer scheduler.deinit();
    var catalog = userspace_loader.Catalog.init();
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_007, 707, 1, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = mebibytes(8),
        .npu_driver_online = true,
    });

    const background = createLoadTask(
        runtime,
        770,
        .background_light,
        "quality-debt-background",
        "app.quality.debt-background",
        load_dispatch_cpu_tick_cost * 2,
        kibibytes(64),
        null,
    );
    const batch = createLoadTask(
        runtime,
        771,
        .batch_compute,
        "quality-debt-batch",
        "app.quality.debt-batch",
        load_dispatch_cpu_tick_cost * 2,
        kibibytes(64),
        null,
    );
    if (!scheduler.registerTask(background.id)) return 0;
    if (!scheduler.registerTask(batch.id)) return 0;
    if (!scheduler.wakeTask(background.id, .timer, 10, 20)) return 0;
    if (!scheduler.wakeTask(batch.id, .timer, 10, 100)) return 0;

    _ = scheduler.runNext(20);
    const background_after_first = scheduler.taskDispatchStats(background.id) orelse return 0;
    const batch_after_first = scheduler.taskDispatchStats(batch.id) orelse return 0;
    if (background_after_first.dispatch_count != 1 or batch_after_first.dispatch_count != 0) return 0;

    if (!scheduler.wakeTask(background.id, .timer, 21, 30)) return 0;
    if (!scheduler.wakeTask(batch.id, .timer, 21, 30)) return 0;
    _ = scheduler.runNext(30);

    const background_stats = scheduler.taskDispatchStats(background.id) orelse return 0;
    const batch_stats = scheduler.taskDispatchStats(batch.id) orelse return 0;
    return @intFromBool(background_stats.dispatch_count == 1 and
        batch_stats.dispatch_count == 1 and
        batch_stats.missed_deadline_count == 0 and
        batch_stats.last_dispatch_engine == .npu);
}

fn qualityAcceleratorClaimDeadlinePriority() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    defer scheduler.deinit();
    var catalog = userspace_loader.Catalog.init();
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_008, 708, 1, .{
        .total_cpu_budget_ticks = 200_000,
        .memory_capacity_bytes = mebibytes(8),
        .gpu_driver_online = true,
    });

    const batch = createLoadTask(
        runtime,
        781,
        .batch_compute,
        "quality-claim-batch",
        "app.quality.claim-batch",
        load_dispatch_cpu_tick_cost * 2,
        kibibytes(64),
        null,
    );
    const foreground = createLoadTask(
        runtime,
        782,
        .foreground_interactive,
        "quality-claim-foreground",
        "app.quality.claim-foreground",
        load_dispatch_cpu_tick_cost * 2,
        kibibytes(64),
        5,
    );
    if (!scheduler.registerTask(batch.id)) return 0;
    if (!scheduler.registerTask(foreground.id)) return 0;
    if (!scheduler.parkTaskUntilEvent(batch.id)) return 0;
    if (!scheduler.parkTaskUntilEvent(foreground.id)) return 0;

    const batch_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = batch.id,
        .engine = .gpu,
        .resource_class = .batch_compute,
        .requested_at_tick = 1,
        .deadline_tick = 200,
        .shared_memory_bytes = kibibytes(64),
    }) orelse return 0;
    const foreground_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = foreground.id,
        .engine = .gpu,
        .resource_class = .foreground_interactive,
        .requested_at_tick = 2,
        .deadline_tick = 20,
        .shared_memory_bytes = kibibytes(64),
    }) orelse return 0;

    const granted = scheduler.grantNextAcceleratorClaim(.gpu, 20) orelse return 0;
    const batch_stats = scheduler.taskDispatchStats(batch.id) orelse return 0;
    const foreground_stats = scheduler.taskDispatchStats(foreground.id) orelse return 0;
    return @intFromBool(batch_claim != foreground_claim and
        granted.id == foreground_claim and
        scheduler.acceleratorClaimQueueDepth(.gpu) == 1 and
        !batch_stats.queued_ready and
        foreground_stats.queued_ready);
}

fn qualityBrokeredAcceleratorQueueCompletionRelease() u64 {
    var controller = accelerator_scheduler.Controller.init();
    controller.configure(.{
        .npu_available = true,
    });
    controller.requireBrokeredEngineQueues();

    const rejected_without_queue = if (controller.claim(.{
        .task_id = 780,
        .request = .{
            .class = .batch_compute,
            .wants_npu = true,
        },
        .require_accelerator = true,
    })) |unexpected_claim| blk: {
        _ = unexpected_claim;
        break :blk false;
    } else |err| err == error.AcceleratorRequired;

    controller.observeBrokeredEngineQueueEvent(.{
        .engine = .npu,
        .broker_task_id = 7_080,
        .owner_task_id = 780,
        .generation = 3,
        .completion_sequence = 30,
        .completion_interrupts_observed = 3,
        .accepts_work = true,
    }) catch return 0;

    const claim = controller.claim(.{
        .task_id = 780,
        .request = .{
            .class = .batch_compute,
            .wants_npu = true,
        },
        .require_accelerator = true,
    }) catch return 0;

    const release_without_completion = if (controller.releaseClaim(claim.id, null)) |unexpected_release| blk: {
        _ = unexpected_release;
        break :blk false;
    } else |err| err == error.QueueCompletionMissing;
    controller.observeBrokeredEngineQueueEvent(.{
        .engine = .npu,
        .broker_task_id = 7_080,
        .owner_task_id = 780,
        .generation = 3,
        .completion_sequence = 31,
        .completion_interrupts_observed = 4,
        .accepts_work = true,
    }) catch return 0;
    const released = controller.releaseClaim(claim.id, null) catch return 0;

    return @intFromBool(rejected_without_queue and
        claim.engine == .npu and
        claim.queue_generation == 3 and
        claim.queue_completion_sequence == 30 and
        release_without_completion and
        released and
        controller.activeClaimCount() == 0);
}

fn qualityBackgroundThrottlingDelayedDispatches() u64 {
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

    var dispatcher = background_dispatch.Controller.init();
    dispatcher.configure(.{
        .max_active_jobs = 2,
        .max_expected_duration_seconds = 300,
        .max_cpu_time_ticks = 2_000,
        .max_memory_bytes = kibibytes(128),
        .max_shared_memory_bytes = kibibytes(64),
    });

    const first = dispatcher.dispatch(runtime, task.id, background_bundle, "sync", .sync_completion, 10) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const second = dispatcher.dispatch(runtime, task.id, background_bundle, "sync", .sync_completion, 11) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const third = dispatcher.dispatch(runtime, task.id, background_bundle, "sync", .sync_completion, 12) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    return @intFromBool(first.allowed and
        second.allowed and
        third.delayed and
        third.reason == .throttled and
        dispatcher.activeRecordCount() == 2);
}

fn qualityLatencyUnderLoadMaxWaitTicks() u64 {
    var executor = userspace_executor.Executor{};
    var scheduler = userspace_scheduler.Scheduler.init(&executor);
    defer scheduler.deinit();
    var catalog = userspace_loader.Catalog.init();
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, runtime, &capabilities);
    configureLoadTelemetry(&scheduler, 7_006, 706, 1, .{
        .total_cpu_budget_ticks = 1_000_000,
        .memory_capacity_bytes = mebibytes(16),
    });

    var background_ids: [LATENCY_BACKGROUND_TASKS]u64 = [_]u64{0} ** LATENCY_BACKGROUND_TASKS;
    for (&background_ids, 0..) |*task_id, index| {
        const task = createLoadTask(
            runtime,
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
        runtime,
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
    var telemetry_counters = counters;
    if (!telemetry_counters.hardware_evidence.complete()) {
        telemetry_counters.hardware_evidence = .{
            .target_id = "benchmark-hardware-telemetry",
            .reader_generation = 1,
            .acpi_observed = true,
            .thermal_observed = true,
            .battery_observed = true,
            .accelerator_observed = true,
            .grid_carbon_observed = true,
        };
    }
    var provider = accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(
        boot_id,
        task_id,
        observed_tick,
        telemetry_counters,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    const service_task = class == .emergency_system_critical;
    const image = if (service_task) benchmarkServiceImage() else benchmarkAppImage();
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
        .initial_component = .{
            .label = label,
            .entry = bundle_id,
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = serial,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = bundle_id,
        },
        .userspace_image = &image,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
}

const DriverRecoveryRuntime = struct {
    const ActivationMode = enum(u8) { userspace_brokered_data_plane };
    const ActivationRecord = struct {
        activation_generation: u32,
        dma_domain_id: u64,
        exclusive_claim: bool,
        mode: ActivationMode,
    };

    deactivation_count: usize = 0,
    activation_count: usize = 0,

    pub fn deactivateDriver(self: *@This(), _: u64, _: driver_service.DeviceClass) bool {
        self.deactivation_count += 1;
        return true;
    }

    pub fn activateAt(self: *@This(), driver: *const driver_service.DriverRecord, _: u64) !ActivationRecord {
        self.activation_count += 1;
        return .{
            .dma_domain_id = driver.dma_domain_id,
            .activation_generation = @intCast(self.activation_count),
            .exclusive_claim = true,
            .mode = .userspace_brokered_data_plane,
        };
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
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = recovery_context.manager.stageImage(0, "stable-a", "kernel=v1", signer("platform-image", 0x72), 10 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = recovery_context.manager.activate(0, .{}, 11 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

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
        ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err),
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
        ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err),
        .parent_version_id = notes_v1.version_id,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const workspace_record = recovery_context.storage.createWorkspace(.{
        .owner = recovery_context.user,
        .label = "recovery-notes",
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    recovery_context.workspace_id = workspace_record.id.raw();
    recovery_context.storage.beginTransaction(workspace_record.id) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    recovery_context.storage.stagePut(
        workspace_record.id,
        "documents/notes.md",
        notes_v1.object_id,
        notes_v1.version_id,
        .document,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = recovery_context.storage.commit(workspace_record.id, 14 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const snapshot = recovery_context.storage.snapshot(
        workspace_record.id,
        "baseline",
        signer("platform-storage", 0x73),
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    recovery_context.snapshot_id = snapshot.id.raw();
    recovery_context.storage.beginTransaction(workspace_record.id) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    recovery_context.storage.stagePut(
        workspace_record.id,
        "documents/notes.md",
        notes_v2.object_id,
        notes_v2.version_id,
        .document,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = recovery_context.storage.commit(workspace_record.id, 15 + iteration) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

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
    _ = sync_port.ensureUserRoot(sync_authority, recovery_context.user, "cameron", signer("platform-user", 0x74)) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = sync_port.enrollTrustedDevice(
        sync_authority,
        recovery_context.user,
        recovery_context.primary_device,
        "primary",
        signer("platform-user", 0x74),
        signer("primary-device", 0x75),
        16 + iteration,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = sync_port.enrollTrustedDevice(
        sync_authority,
        recovery_context.user,
        recovery_context.tablet,
        "tablet",
        signer("platform-user", 0x74),
        signer("tablet-device", 0x76),
        17 + iteration,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const local_policy = sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "local-net",
        .mode = .local_network,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_record.id.raw(),
        .owner = recovery_context.user,
        .device_to_device_policy_id = local_policy.id,
        .selective_prefixes = &.{"documents/"},
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    sync_port.setReplicaVersion(
        sync_authority,
        workspace_record.id.raw(),
        recovery_context.tablet,
        "documents/notes.md",
        notes_v1.object_id,
        notes_v1.version_id,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

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
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    update_health_context.sync = sync_service.Service.init(1_500, 401, owner);
    update_health_context.sync_capabilities = capability.CapabilityTable.init();
    update_health_context.compositor = compositor_session.Session.init();
    update_health_context.supervisor = supervisor_mod.Supervisor.init();
    update_health_context.ledger.reset();

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
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

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
    const service_record = supervisor.register(class, owner) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    const record = storage.putLocallySignedVersion(.{
        .preferred_object_id = ids.object(7_700),
        .object_type = .document,
        .payload = "notes-v1",
        .signer = identity,
        .label = "notes",
        .content_type = "text/plain",
        .created_at_ticks = tick,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const workspace_record = storage.createWorkspace(.{
        .owner = owner,
        .label = "update-health",
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    storage.beginTransaction(workspace_record.id) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    storage.stagePut(workspace_record.id, "documents/notes.md", record.object_id, record.version_id, .document) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = storage.commit(workspace_record.id, tick + 1) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
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
    _ = port.ensureUserRoot(authority, owner, "update-health", signer("update-health-user", 0x51)) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = port.enrollTrustedDevice(
        authority,
        owner,
        source_device,
        "source",
        signer("update-health-user", 0x51),
        signer("update-health-source", 0x52),
        tick_base,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = port.enrollTrustedDevice(
        authority,
        owner,
        target_device,
        "target",
        signer("update-health-user", 0x51),
        signer("update-health-target", 0x53),
        tick_base + 1,
    ) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

    const local_policy = port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "health-local",
        .mode = .local_network,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    const overlay_policy = port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "health-overlay",
        .mode = .named_service_identity,
        .target = "overlay.health.sync",
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_id,
        .owner = owner,
        .device_to_device_policy_id = local_policy.id,
        .overlay_policy_id = overlay_policy.id,
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = port.configureOverlay(authority, workspace_id, source_device, "overlay.health.sync", true) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);

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
    quality_gate_runtime.reset();
    const runtime = &quality_gate_runtime;
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    _ = session.openTaskView(task, "Update Health") catch |err| benchmark_reporting.benchStepFailure("benchmark suite", err);
    return .{ .session = session };
}

fn resolveBridgeEntry(
    context: *const anyopaque,
    workspace_id: u64,
    path: []const u8,
) workspace.Error!*const workspace.Entry {
    const bridge_context: *const FileBridgeContext = @ptrCast(@alignCast(context));
    if (workspace_id != bridge_context.expected_workspace_id) return error.EntryNotFound;
    if (!std.mem.eql(u8, path, bridge_context.expected_path)) return error.EntryNotFound;
    return &bridge_context.entry;
}

fn bridgeHasVersion(context: *const anyopaque, version_id: u64) bool {
    const bridge_context: *const FileBridgeContext = @ptrCast(@alignCast(context));
    return bridge_context.version_present and version_id == bridge_context.expected_version_id;
}
