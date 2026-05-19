const std = @import("std");
const abi = @import("../core/abi.zig");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const generated_image_fixtures = if (@import("builtin").is_test) @import("../task/generated_image_fixtures.zig") else struct {};
const immutable_base = @import("../platform/immutable_base.zig");
const object_store = @import("../storage/object_store.zig");
const platform_policy_signals = @import("../platform/platform_policy_signals.zig");
const principal = @import("../core/principal.zig");
const session_manager = @import("session_manager.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("../sync/sync_service.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("../task/task_runtime.zig");
const update_health = @import("../platform/update_health.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const common = @import("service_path_proofs_common.zig");

const createBootedServiceTask = common.createBootedServiceTask;
const signer = common.signer;

pub fn proveBootedPostActivationHealthChecks(
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    supervisor: *supervisor_mod.Supervisor,
    storage: *storage_service.Service,
    sync_task: *task_runtime.TaskRecord,
    compositor_session_ptr: *compositor_session.Session,
) !void {
    const owner = principal.PrincipalId{ .kind = .service, .serial = 81_200 };
    const state_signer = signer("booted-health-state", 0x72);
    const image_signer = signer("booted-health-image", 0x73);
    const object_signer = signer("booted-health-storage", 0x74);
    const workspace_id = try seedBootedHealthStorageProbe(storage, owner, object_signer);

    const sync_record = supervisor.findByClass(.sync_replication) orelse return error.MissingBootedHealthService;
    var sync_instance = try sync_service.Service.initWithStorage(
        sync_record.id,
        sync_task.id,
        sync_record.owner,
        storage,
        session_manager.system().syncResidentStatePtr(),
    );
    const network_probe = try seedBootedHealthNetworkProbe(&sync_instance, capability_table, workspace_id, 600);

    const policy_service_id = (supervisor.findByClass(.policy_mediation) orelse return error.MissingBootedHealthService).id;
    const package_service_id = (supervisor.findByClass(.package_install_update) orelse return error.MissingBootedHealthService).id;
    const sync_service_id = sync_record.id;
    const network_service_id = (supervisor.findByClass(.network_stack) orelse return error.MissingBootedHealthService).id;
    const ui_service_id = (supervisor.findByClass(.compositor_ui_session) orelse return error.MissingBootedHealthService).id;
    const core_service_ids = [_]u64{ policy_service_id, package_service_id, sync_service_id };
    const healthy_request = update_health.CheckRequest{
        .core_service_ids = core_service_ids[0..],
        .storage_workspace_id = workspace_id,
        .storage_probe_path = "health/state.txt",
        .network_service_id = network_service_id,
        .ui_service_id = ui_service_id,
        .network_probe = network_probe,
        .ui_probe = .{ .session = compositor_session_ptr },
        .require_service_path_probes = true,
    };

    var manager = try immutable_base.Manager.init(storage, owner, state_signer);
    var ledger = event_ledger.Ledger.init();
    _ = try manager.stageImage(0, "booted-stable-a", "kernel=booted-v1", image_signer, 610);
    try manager.beginActivation(0, 611);
    try update_health.recordBootSuccess(&manager, 612);
    const first_activation = try update_health.validatePendingActivation(&manager, supervisor, storage, healthy_request, &ledger, 613);
    try std.testing.expect(!first_activation.activation.rolled_back);
    try std.testing.expectEqual(@as(?usize, 0), first_activation.activation.active_slot);

    _ = try manager.stageImage(1, "booted-stable-b", "kernel=booted-v2", image_signer, 614);

    const FailureCase = struct {
        expected: immutable_base.HealthFailure,
        request: update_health.CheckRequest,
        crash_service_id: ?u64 = null,
    };
    const cases = [_]FailureCase{
        .{
            .expected = .boot,
            .request = healthy_request,
        },
        .{
            .expected = .core_service,
            .request = healthy_request,
            .crash_service_id = sync_service_id,
        },
        .{
            .expected = .storage,
            .request = .{
                .core_service_ids = core_service_ids[0..],
                .storage_workspace_id = workspace_id,
                .storage_probe_path = "health/missing.txt",
                .network_service_id = network_service_id,
                .ui_service_id = ui_service_id,
                .network_probe = network_probe,
                .ui_probe = .{ .session = compositor_session_ptr },
                .require_service_path_probes = true,
            },
        },
        .{
            .expected = .network,
            .request = .{
                .core_service_ids = core_service_ids[0..],
                .storage_workspace_id = workspace_id,
                .storage_probe_path = "health/state.txt",
                .network_service_id = network_service_id,
                .ui_service_id = ui_service_id,
                .ui_probe = .{ .session = compositor_session_ptr },
                .require_service_path_probes = true,
            },
        },
        .{
            .expected = .ui,
            .request = .{
                .core_service_ids = core_service_ids[0..],
                .storage_workspace_id = workspace_id,
                .storage_probe_path = "health/state.txt",
                .network_service_id = network_service_id,
                .ui_service_id = ui_service_id,
                .network_probe = network_probe,
                .require_service_path_probes = true,
            },
        },
    };

    for (cases, 0..) |case, index| {
        const tick_base = 620 + @as(u64, @intCast(index * 10));
        try manager.beginActivation(1, tick_base);
        if (case.expected != .boot) try update_health.recordBootSuccess(&manager, tick_base + 1);
        if (case.crash_service_id) |service_id| {
            try std.testing.expect(supervisor.recordCrash(service_id, tick_base + 2, 0xB007_0000 + @as(u32, @intCast(index))));
        }
        const result = try update_health.validatePendingActivation(&manager, supervisor, storage, case.request, &ledger, tick_base + 3);
        try std.testing.expect(result.activation.rolled_back);
        try std.testing.expectEqual(case.expected, result.activation.failure);
        try std.testing.expectEqual(@as(?usize, 0), result.activation.active_slot);
        if (case.crash_service_id) |service_id| {
            try std.testing.expect(supervisor.markHealthy(service_id, tick_base + 4));
        }
    }

    try manager.beginActivation(1, 680);
    try update_health.recordBootSuccess(&manager, 681);
    const success = try update_health.validatePendingActivation(&manager, supervisor, storage, healthy_request, &ledger, 682);
    try std.testing.expect(!success.activation.rolled_back);
    try std.testing.expectEqual(@as(?usize, 1), success.activation.active_slot);
    try std.testing.expectEqual(@as(u64, cases.len), success.activation.rollback_generation);
    try std.testing.expect(manager.verifyActiveImage());

    var export_buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    for (cases) |case| {
        var needle_buffer: [48]u8 = undefined;
        const needle = try std.fmt.bufPrint(&needle_buffer, "failure={s}", .{@tagName(case.expected)});
        try std.testing.expect(std.mem.indexOf(u8, exported, needle) != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=none") != null);
    _ = runtime;
}

fn seedBootedHealthStorageProbe(
    storage: *storage_service.Service,
    owner: principal.PrincipalId,
    signer_identity: signing.SignerIdentity,
) !u64 {
    const record = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(81_200),
        .object_type = .document,
        .payload = "booted-health-ok",
        .metadata = try object_store.signMetadata(
            signer_identity,
            "booted-health-state",
            "text/plain",
            .document,
            "booted-health-ok",
            590,
        ),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = owner,
        .label = "booted-health-checks",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "health/state.txt", record.object_id, record.version_id, .document);
    _ = try storage.commit(workspace_record.id, 591);
    return workspace_record.id.raw();
}

fn seedBootedHealthNetworkProbe(
    sync: *sync_service.Service,
    capability_table: *capability.CapabilityTable,
    workspace_id: u64,
    tick_base: u64,
) !update_health.NetworkProbe {
    const user = principal.PrincipalId{ .kind = .user, .serial = 81_201 };
    const source_device = principal.PrincipalId{ .kind = .device, .serial = 81_202 };
    const target_device = principal.PrincipalId{ .kind = .device, .serial = 81_203 };
    const user_signer = signer("booted-health-user", 0x75);
    const source_signer = signer("booted-health-source", 0x76);
    const target_signer = signer("booted-health-target", 0x77);

    const authority_capability = try capability_table.mintBootRoot(.{
        .holder = sync.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = sync.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
        } },
        .scope = .{
            .task_id = sync.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = tick_base,
            .expires_at_ticks = tick_base + 1_000,
        },
    });
    var port = sync_service.SyncPort.init(sync, capability_table);
    const authority = sync_service.AuthorityContext{
        .task_id = sync.task_id,
        .principal = sync.owner,
        .capability_id = authority_capability.id,
        .now_ticks = tick_base,
    };

    _ = try port.ensureUserRoot(authority, user, "booted-health", user_signer);
    _ = try port.enrollTrustedDevice(authority, user, source_device, "source", user_signer, source_signer, tick_base + 1);
    _ = try port.enrollTrustedDevice(authority, user, target_device, "target", user_signer, target_signer, tick_base + 2);

    const local_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "booted-health-local",
        .mode = .local_network,
    });
    const overlay_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "booted-health-overlay",
        .mode = .named_service_identity,
        .target = "overlay.booted.health",
    });
    _ = try port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
        .overlay_policy_id = overlay_policy.id,
    });
    _ = try port.configureOverlay(authority, workspace_id, source_device, "overlay.booted.health", true);

    return .{
        .sync = sync,
        .capability_table = capability_table,
        .authority = authority,
        .workspace_id = workspace_id,
        .source_device = source_device,
        .target_device = target_device,
        .tick = tick_base + 3,
    };
}

pub fn proveBootedSchedulerTelemetryProvider(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    scheduler: *userspace_scheduler.Scheduler,
    session_task_id: u64,
    session_authority_id: u64,
) !void {
    parkBootedSchedulerTasks(runtime, scheduler);

    const provider_owner = principal.PrincipalId{ .kind = .service, .serial = 81_000 };
    const provider_task = try createBootedServiceTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        provider_owner,
        81_000,
        "platform-resource-provider",
        "zigos.system.resource-telemetry",
        700,
    );
    const foreground_image = try generated_image_fixtures.appImage();
    const foreground = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 81_001 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 1,
            .shared_memory_bytes = 4096,
            .resource_class = .foreground_interactive,
        },
        .ui_surface_id = 44,
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 81_001,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = "app.service-path.telemetry-ui",
        },
        .userspace_image = &foreground_image,
    });
    try std.testing.expect(runtime.processSeparated(provider_task.task_id, foreground.id));
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(foreground.id, .{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = 4096,
    }, false));

    var provider = try platform_policy_signals.FreestandingPlatformTelemetryProvider.initForBootedService(
        44,
        provider_task.task_id,
        701,
        platform_policy_signals.collectLiveCounters(runtime, scheduler, .{
            .thermal_milli_celsius = 91_000,
            .battery_percent = 15,
            .battery_charging = false,
            .gpu_driver_online = true,
            .npu_driver_online = false,
            .media_driver_online = true,
        }),
    );
    try std.testing.expectError(error.TelemetryProviderUnauthorized, provider.observeLive(
        session_task_id,
        701,
        platform_policy_signals.collectLiveCounters(runtime, scheduler, .{}),
    ));
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expectEqual(accelerator_scheduler.TelemetrySource.hardware, scheduler.resource_telemetry_source);
    try std.testing.expectEqual(@as(u64, 701), scheduler.resource_telemetry_observed_tick);
    try std.testing.expectEqual(accelerator_scheduler.ThermalPressure.critical, scheduler.resource_state.thermal_pressure);
    try std.testing.expect(scheduler.resource_state.battery_saver);
    try std.testing.expect(scheduler.resource_state.gpu_available);
    try std.testing.expect(!scheduler.resource_state.npu_available);
    try std.testing.expect(scheduler.resource_state.media_available);
    try std.testing.expect(scheduler.resource_state.cpu_budget_ticks > 0);
    try std.testing.expect(scheduler.resource_state.memory_bandwidth_units > 0);
    try std.testing.expectEqual(@as(u32, 1), provider.liveObservationCount());
    try std.testing.expectEqual(@as(u32, 1), provider.rejectedObservationCount());

    try std.testing.expect(!scheduler.runNext(701));
    const foreground_slot = scheduler.slots.getConst(foreground.id).?;
    try std.testing.expectEqual(@as(u64, 1), foreground_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, foreground_slot.last_dispatch_engine);
    try std.testing.expect(foreground_slot.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, foreground_slot.last_dispatch_reason);

    const media_image = try generated_image_fixtures.appImage();
    const media = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 81_002 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = 64 * 1024,
            .endpoint_slots = 1,
            .shared_memory_bytes = 8192,
            .resource_class = .media_export,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 81_002,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = "app.service-path.telemetry-media",
        },
        .userspace_image = &media_image,
    });
    try std.testing.expect(runtime.processSeparated(provider_task.task_id, media.id));
    try std.testing.expect(scheduler.registerTask(media.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(media.id, .{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = 8192,
    }, true));

    const media_denials_before = scheduler.engineDenialCount(.media);
    try provider.observeLive(provider_task.task_id, 702, platform_policy_signals.collectLiveCounters(runtime, scheduler, .{
        .thermal_milli_celsius = 45_000,
        .battery_percent = 15,
        .battery_charging = false,
        .gpu_driver_online = false,
        .npu_driver_online = false,
        .media_driver_online = false,
    }));
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expectEqual(@as(u64, 702), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(scheduler.resource_state.battery_saver);
    try std.testing.expect(!scheduler.resource_state.gpu_available);
    try std.testing.expect(!scheduler.resource_state.npu_available);
    try std.testing.expect(!scheduler.resource_state.media_available);
    try std.testing.expect(!scheduler.runNext(702));
    const denied_media_slot = scheduler.slots.getConst(media.id).?;
    try std.testing.expectEqual(@as(u64, 0), denied_media_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), denied_media_slot.denied_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.accelerator_unavailable, denied_media_slot.last_dispatch_reason);
    try std.testing.expectEqual(media_denials_before + 1, scheduler.engineDenialCount(.media));
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    try provider.observeLive(provider_task.task_id, 703, platform_policy_signals.collectLiveCounters(runtime, scheduler, .{
        .thermal_milli_celsius = 45_000,
        .battery_percent = 15,
        .battery_charging = false,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
    }));
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expectEqual(@as(u64, 703), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(scheduler.resource_state.gpu_available);
    try std.testing.expect(scheduler.resource_state.npu_available);
    try std.testing.expect(scheduler.resource_state.media_available);
    try std.testing.expect(!scheduler.runNext(703));
    const dispatched_media_slot = scheduler.slots.getConst(media.id).?;
    try std.testing.expectEqual(@as(u64, 1), dispatched_media_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, dispatched_media_slot.last_dispatch_engine);
    try std.testing.expect(dispatched_media_slot.last_dispatch_zero_copy);
    try std.testing.expect(dispatched_media_slot.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.battery_preserve, dispatched_media_slot.last_dispatch_reason);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(u32, 3), provider.liveObservationCount());
    try std.testing.expectEqual(@as(u32, 3), provider.readCount());
}

fn parkBootedSchedulerTasks(
    runtime: *task_runtime.Runtime,
    scheduler: *userspace_scheduler.Scheduler,
) void {
    var slot_index: usize = 0;
    while (slot_index < runtime.taskSlotCapacity()) : (slot_index += 1) {
        const slot = runtime.taskSlotAtConst(slot_index);
        if (!slot.in_use) continue;
        _ = scheduler.parkTaskUntilEvent(slot.task.id);
    }
}
