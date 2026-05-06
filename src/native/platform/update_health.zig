const std = @import("std");
const compositor_session = @import("compositor_session.zig");
const event_ledger = @import("event_ledger.zig");
const immutable_base = @import("immutable_base.zig");
const contract = @import("../session/contract.zig");
const native_util = @import("../core/util.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const supervisor_mod = @import("../session/supervisor.zig");

const yesNo = native_util.yesNo;

pub const CheckRequest = struct {
    core_service_ids: []const u64,
    storage_workspace_id: u64,
    storage_probe_path: []const u8,
    network_service_id: u64,
    ui_service_id: u64,
    network_probe: ?NetworkProbe = null,
    ui_probe: ?UiProbe = null,
};

pub const NetworkProbe = struct {
    sync: *sync_service.Service,
    workspace_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    usage: sync_service.OverlaySessionUse = .sync_replication,
    transport: sync_service.TransportMode = .device_to_device,
    private_service_label: ?[]const u8 = null,
    tick: u64,
};

pub const UiProbe = struct {
    session: *const compositor_session.Session,
};

const boot_witness_entry_path = "state/boot-success";
const boot_witness_magic: u32 = 0x42575431;

const BootWitness = extern struct {
    magic: u32 = boot_witness_magic,
    slot_index: u8 = 0,
    _reserved: [3]u8 = [_]u8{0} ** 3,
    activation_generation: u64 = 0,
    tick: u64 = 0,
};

pub const CheckEvaluation = struct {
    report: immutable_base.HealthReport,
    core_services_started: usize,
    storage_probe_ok: bool,
    network_service_ok: bool,
    ui_service_ok: bool,
};

pub const ActivationCheckResult = struct {
    evaluation: CheckEvaluation,
    activation: immutable_base.ActivationResult,
};

pub fn evaluate(
    manager: *immutable_base.Manager,
    supervisor: *supervisor_mod.Supervisor,
    storage: *const storage_service.Service,
    request: CheckRequest,
) CheckEvaluation {
    const core_services_started = countStartedServices(supervisor, request.core_service_ids);
    const storage_probe_ok = storageMountHealthy(storage, request.storage_workspace_id, request.storage_probe_path);
    const network_service_ok = serviceStarted(supervisor, request.network_service_id) and networkServiceHealthy(request.network_probe);
    const ui_service_ok = serviceStarted(supervisor, request.ui_service_id) and uiServiceHealthy(request.ui_probe);
    const boot_ok = bootActivationHealthy(manager);

    return .{
        .report = .{
            .boot_ok = boot_ok,
            .core_services_ok = core_services_started == request.core_service_ids.len,
            .storage_ok = storage_probe_ok,
            .network_ok = network_service_ok,
            .ui_ok = ui_service_ok,
        },
        .core_services_started = core_services_started,
        .storage_probe_ok = storage_probe_ok,
        .network_service_ok = network_service_ok,
        .ui_service_ok = ui_service_ok,
    };
}

pub fn validatePendingActivation(
    manager: *immutable_base.Manager,
    supervisor: *supervisor_mod.Supervisor,
    storage: *const storage_service.Service,
    request: CheckRequest,
    ledger: ?*event_ledger.Ledger,
    tick: u64,
) immutable_base.Error!ActivationCheckResult {
    const evaluation = evaluate(manager, supervisor, storage, request);
    const candidate_slot_index = manager.pendingSlotIndex() orelse if (manager.activeImage()) |image|
        image.slot_index
    else
        0;
    const activation = try manager.finalizeActivation(evaluation.report, tick);

    if (ledger) |recording| {
        var detail_buffer: [160]u8 = undefined;
        const detail = renderTransitionDetail(
            &detail_buffer,
            @as(usize, candidate_slot_index),
            evaluation.report,
            activation,
        );
        try recording.recordUpdateTransition(
            manager.owner,
            @as(usize, candidate_slot_index),
            activation.failure,
            activation.rolled_back,
            tick,
            detail,
        );
    }

    return .{
        .evaluation = evaluation,
        .activation = activation,
    };
}

pub fn recordBootSuccess(
    manager: *immutable_base.Manager,
    tick: u64,
) immutable_base.Error!void {
    if (manager.pendingSlotIndex() == null) return error.NoPendingActivation;
    const active_image = manager.activeImage() orelse return error.ImageNotPresent;
    var witness = BootWitness{
        .slot_index = active_image.slot_index,
        .activation_generation = manager.activation_generation,
        .tick = tick,
    };
    const payload = std.mem.asBytes(&witness);
    const existing_entry = manager.storage.resolve(manager.workspace_id, boot_witness_entry_path) catch |err| switch (err) {
        error.EntryNotFound => null,
        else => return err,
    };
    const result = try manager.storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(bootWitnessObjectId()),
        .object_type = .document,
        .payload = payload,
        .metadata = try object_store.signMetadata(
            manager.state_signer,
            "update-health-boot-success",
            "application/zigos-update-health-boot-success",
            .document,
            payload,
            tick,
        ),
        .parent_version_id = if (existing_entry) |entry| entry.version_id else null,
    });
    try manager.storage.beginTransaction(manager.workspace_id);
    try manager.storage.stagePut(manager.workspace_id, boot_witness_entry_path, result.object_id, result.version_id, .document);
    _ = try manager.storage.commit(manager.workspace_id, tick);
}

fn countStartedServices(supervisor: *supervisor_mod.Supervisor, service_ids: []const u64) usize {
    var ready_count: usize = 0;
    for (service_ids) |service_id| {
        if (serviceStarted(supervisor, service_id)) ready_count += 1;
    }
    return ready_count;
}

fn bootActivationHealthy(manager: *immutable_base.Manager) bool {
    const active_image = manager.activeImage() orelse return false;
    if (!manager.verifySlot(active_image.slot_index)) return false;
    const witness = loadBootWitness(manager) catch return false;
    return witness.slot_index == active_image.slot_index and
        witness.activation_generation == manager.activation_generation;
}

fn storageMountHealthy(storage: *const storage_service.Service, workspace_id: u64, path: []const u8) bool {
    const workspace_record = storage.findWorkspaceRecordConst(workspace_id) orelse return false;
    if (workspace_record.generation == 0 and workspace_record.entry_count == 0) return false;

    const entries = storage.entries(workspace_id) catch return false;
    if (path.len == 0) return entries.len != 0 or workspace_record.generation != 0;

    const resolved = storage.resolve(workspace_id, path) catch return false;
    if (resolved.version_id.isZero() or resolved.object_id.isZero()) return false;
    const version = storage.version(resolved.version_id) orelse return false;
    if (!version.object_id.eql(resolved.object_id)) return false;
    _ = storage.object(resolved.object_id) orelse return false;
    const payload = storage.versionPayload(version) catch return false;
    return version.metadata.verifyFor(version.object_type, payload);
}

fn serviceStarted(supervisor: *supervisor_mod.Supervisor, service_id: u64) bool {
    const service = supervisor.find(service_id) orelse return false;
    return service.state == .healthy and
        supervisor.hasDiagnostic(service_id, .healthy) and
        supervisor.hasDiagnostic(service_id, .contract_bound);
}

fn networkServiceHealthy(probe: ?NetworkProbe) bool {
    const check = probe orelse return true;
    const session = check.sync.openOverlaySession(
        check.workspace_id,
        check.source_device,
        check.target_device,
        check.usage,
        check.transport,
        check.private_service_label,
        check.tick,
    ) catch return false;
    _ = check.sync.probeOverlaySession(session.session_id, check.tick + 1) catch {
        _ = check.sync.closeOverlaySession(session.session_id, check.tick + 2) catch return false;
        return false;
    };
    const live = check.sync.findOverlaySession(session.session_id) orelse {
        _ = check.sync.closeOverlaySession(session.session_id, check.tick + 2) catch return false;
        return false;
    };
    const healthy = live.isActive() and live.keepalive_count != 0;
    _ = check.sync.closeOverlaySession(session.session_id, check.tick + 2) catch return false;
    return healthy;
}

fn uiServiceHealthy(probe: ?UiProbe) bool {
    const check = probe orelse return true;
    var buffer: [320]u8 = undefined;
    return check.session.probeVisibleWindow(&buffer);
}

fn renderTransitionDetail(
    buffer: []u8,
    slot_index: usize,
    report: immutable_base.HealthReport,
    activation: immutable_base.ActivationResult,
) []const u8 {
    return std.fmt.bufPrint(
        buffer,
        "slot={d} boot={s} core={s} storage={s} network={s} ui={s} rollback={s} failure={s}",
        .{
            slot_index,
            yesNo(report.boot_ok),
            yesNo(report.core_services_ok),
            yesNo(report.storage_ok),
            yesNo(report.network_ok),
            yesNo(report.ui_ok),
            yesNo(activation.rolled_back),
            @tagName(activation.failure),
        },
    ) catch "update-transition";
}

fn loadBootWitness(manager: *immutable_base.Manager) immutable_base.Error!BootWitness {
    const entry = try manager.storage.resolve(manager.workspace_id, boot_witness_entry_path);
    const version = manager.storage.version(entry.version_id) orelse return error.CorruptState;
    const payload = try manager.storage.versionPayload(version);
    if (payload.len != @sizeOf(BootWitness)) return error.CorruptState;

    var witness = std.mem.zeroes(BootWitness);
    @memcpy(std.mem.asBytes(&witness), payload);
    if (witness.magic != boot_witness_magic) return error.CorruptState;
    return witness;
}

fn bootWitnessObjectId() u64 {
    return native_util.fnv1a64WithSeed(0xB0075CC355000001, "platform:update-health:boot-success");
}

fn registerHealthyService(
    supervisor: *supervisor_mod.Supervisor,
    class: contract.ServiceClass,
    owner: principal.PrincipalId,
    tick: u64,
) !u64 {
    const service = try supervisor.register(class, owner);
    try std.testing.expect(supervisor.noteContractBound(service.id, 100 + service.id, tick));
    try std.testing.expect(supervisor.markHealthy(service.id, tick));
    return service.id;
}

fn seedStorageProbe(
    storage: *storage_service.Service,
    owner: principal.PrincipalId,
    signer: signing.SignerIdentity,
) !u64 {
    const record = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(7_700),
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(
            signer,
            "notes",
            "text/plain",
            .document,
            "notes-v1",
            9,
        ),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = owner,
        .label = "update-health",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", record.object_id, record.version_id, .document);
    _ = try storage.commit(workspace_record.id, 10);
    return workspace_record.id.raw();
}

fn seedNetworkProbe(
    sync: *sync_service.Service,
    workspace_id: u64,
    tick_base: u64,
) !NetworkProbe {
    const user = principal.PrincipalId{ .kind = .user, .serial = 88 };
    const source_device = principal.PrincipalId{ .kind = .device, .serial = 881 };
    const target_device = principal.PrincipalId{ .kind = .device, .serial = 882 };
    const user_signer = signing.SignerIdentity{
        .label = "update-health-user",
        .seed = [_]u8{0x51} ** 32,
    };
    const source_signer = signing.SignerIdentity{
        .label = "update-health-source",
        .seed = [_]u8{0x52} ** 32,
    };
    const target_signer = signing.SignerIdentity{
        .label = "update-health-target",
        .seed = [_]u8{0x53} ** 32,
    };

    _ = try sync.ensureUserRoot(user, "update-health", user_signer);
    _ = try sync.enrollTrustedDevice(user, source_device, "source", user_signer, source_signer, tick_base);
    _ = try sync.enrollTrustedDevice(user, target_device, "target", user_signer, target_signer, tick_base + 1);

    const local_policy = try sync.createNetworkPolicy(.{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "health-local",
        .mode = .local_network,
    });
    const overlay_policy = try sync.createNetworkPolicy(.{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "health-overlay",
        .mode = .named_service_identity,
        .target = "overlay.health.sync",
    });
    _ = try sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_id,
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
        .overlay_policy_id = overlay_policy.id,
    });
    _ = try sync.configureOverlay(workspace_id, source_device, "overlay.health.sync", true);

    return .{
        .sync = sync,
        .workspace_id = workspace_id,
        .source_device = source_device,
        .target_device = target_device,
        .tick = tick_base + 2,
    };
}

fn seedUiProbe(session: *compositor_session.Session) !UiProbe {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 89 },
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
    });
    _ = try session.openTaskView(task, "Update Health");
    return .{ .session = session };
}

test "update health validates boot core storage network and ui checks and records update history" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 70 };
    const state_signer = signing.SignerIdentity{
        .label = "update-health-state",
        .seed = [_]u8{0x31} ** 32,
    };
    const image_signer = signing.SignerIdentity{
        .label = "update-health-image",
        .seed = [_]u8{0x32} ** 32,
    };
    const object_signer = signing.SignerIdentity{
        .label = "update-health-object",
        .seed = [_]u8{0x33} ** 32,
    };

    var storage = storage_service.Service.initWithStore(1_001, 201, owner, &storage_checkpoint_store);
    const probe_workspace_id = try seedStorageProbe(&storage, owner, object_signer);
    var manager = try immutable_base.Manager.init(&storage, owner, state_signer);
    var sync = sync_service.Service.init(1_500, 401, owner);
    const network_probe = try seedNetworkProbe(&sync, probe_workspace_id, 12);
    var compositor = compositor_session.Session.init();
    const ui_probe = try seedUiProbe(&compositor);
    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 11);

    var supervisor = supervisor_mod.Supervisor.init();
    const policy_service_id = try registerHealthyService(&supervisor, .policy_mediation, owner, 12);
    const package_service_id = try registerHealthyService(&supervisor, .package_install_update, owner, 12);
    const sync_service_id = try registerHealthyService(&supervisor, .sync_replication, owner, 12);
    const network_service_id = try registerHealthyService(&supervisor, .network_stack, owner, 12);
    const ui_service_id = try registerHealthyService(&supervisor, .compositor_ui_session, owner, 12);
    const core_service_ids = [_]u64{ policy_service_id, package_service_id, sync_service_id };

    const request = CheckRequest{
        .core_service_ids = core_service_ids[0..],
        .storage_workspace_id = probe_workspace_id,
        .storage_probe_path = "documents/notes.md",
        .network_service_id = network_service_id,
        .ui_service_id = ui_service_id,
        .network_probe = network_probe,
        .ui_probe = ui_probe,
    };

    var ledger = event_ledger.Ledger.init();
    try manager.beginActivation(0, 13);
    try recordBootSuccess(&manager, 14);
    const result = try validatePendingActivation(&manager, &supervisor, &storage, request, &ledger, 15);

    try std.testing.expect(result.evaluation.report.isHealthy());
    try std.testing.expectEqual(@as(usize, core_service_ids.len), result.evaluation.core_services_started);
    try std.testing.expect(result.evaluation.storage_probe_ok);
    try std.testing.expect(result.evaluation.network_service_ok);
    try std.testing.expect(result.evaluation.ui_service_ok);
    try std.testing.expect(!result.activation.rolled_back);
    try std.testing.expectEqual(@as(?usize, 0), result.activation.active_slot);

    const update_event = ledger.latestKind(.update_transition).?;
    try std.testing.expect(update_event.allowed);
    try std.testing.expectEqual(@as(u64, 0), update_event.related_id);
    try std.testing.expectEqual(@as(u32, @intFromEnum(immutable_base.HealthFailure.none)), update_event.detail_code);
    try std.testing.expect(std.mem.indexOf(u8, update_event.detailSlice(), "boot=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, update_event.detailSlice(), "failure=none") != null);
}

test "update health failures trigger rollback for each required post-activation check" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();
    defer storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 71 };
    const state_signer = signing.SignerIdentity{
        .label = "update-health-state-v2",
        .seed = [_]u8{0x41} ** 32,
    };
    const image_signer = signing.SignerIdentity{
        .label = "update-health-image-v2",
        .seed = [_]u8{0x42} ** 32,
    };
    const object_signer = signing.SignerIdentity{
        .label = "update-health-object-v2",
        .seed = [_]u8{0x43} ** 32,
    };

    var storage = storage_service.Service.initWithStore(1_002, 202, owner, &storage_checkpoint_store);
    const probe_workspace_id = try seedStorageProbe(&storage, owner, object_signer);
    var manager = try immutable_base.Manager.init(&storage, owner, state_signer);
    var sync = sync_service.Service.init(1_501, 402, owner);
    const network_probe = try seedNetworkProbe(&sync, probe_workspace_id, 20);
    var compositor = compositor_session.Session.init();
    const ui_probe = try seedUiProbe(&compositor);

    var supervisor = supervisor_mod.Supervisor.init();
    const policy_service_id = try registerHealthyService(&supervisor, .policy_mediation, owner, 20);
    const package_service_id = try registerHealthyService(&supervisor, .package_install_update, owner, 20);
    const sync_service_id = try registerHealthyService(&supervisor, .sync_replication, owner, 20);
    const network_service_id = try registerHealthyService(&supervisor, .network_stack, owner, 20);
    const ui_service_id = try registerHealthyService(&supervisor, .compositor_ui_session, owner, 20);
    const core_service_ids = [_]u64{ policy_service_id, package_service_id, sync_service_id };
    const healthy_request = CheckRequest{
        .core_service_ids = core_service_ids[0..],
        .storage_workspace_id = probe_workspace_id,
        .storage_probe_path = "documents/notes.md",
        .network_service_id = network_service_id,
        .ui_service_id = ui_service_id,
        .network_probe = network_probe,
        .ui_probe = ui_probe,
    };

    var ledger = event_ledger.Ledger.init();

    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 21);
    try manager.beginActivation(0, 22);
    try recordBootSuccess(&manager, 23);
    const first_activation = try validatePendingActivation(&manager, &supervisor, &storage, healthy_request, &ledger, 24);
    try std.testing.expect(!first_activation.activation.rolled_back);

    _ = try manager.stageImage(1, "stable-b", "kernel=v2", image_signer, 25);

    try manager.beginActivation(1, 26);
    const boot_failure = try validatePendingActivation(&manager, &supervisor, &storage, healthy_request, &ledger, 27);
    try std.testing.expect(boot_failure.activation.rolled_back);
    try std.testing.expectEqual(immutable_base.HealthFailure.boot, boot_failure.activation.failure);

    try manager.beginActivation(1, 28);
    try recordBootSuccess(&manager, 29);
    try std.testing.expect(supervisor.recordCrash(sync_service_id, 30, 0xC0DE));
    const core_failure = try validatePendingActivation(&manager, &supervisor, &storage, healthy_request, &ledger, 31);
    try std.testing.expect(core_failure.activation.rolled_back);
    try std.testing.expectEqual(immutable_base.HealthFailure.core_service, core_failure.activation.failure);
    try std.testing.expect(supervisor.markHealthy(sync_service_id, 32));

    try manager.beginActivation(1, 33);
    try recordBootSuccess(&manager, 34);
    const storage_failure = try validatePendingActivation(&manager, &supervisor, &storage, .{
        .core_service_ids = core_service_ids[0..],
        .storage_workspace_id = probe_workspace_id,
        .storage_probe_path = "documents/missing.md",
        .network_service_id = network_service_id,
        .ui_service_id = ui_service_id,
        .network_probe = network_probe,
        .ui_probe = ui_probe,
    }, &ledger, 35);
    try std.testing.expect(storage_failure.activation.rolled_back);
    try std.testing.expectEqual(immutable_base.HealthFailure.storage, storage_failure.activation.failure);

    try manager.beginActivation(1, 36);
    try recordBootSuccess(&manager, 37);
    try std.testing.expect(supervisor.recordCrash(network_service_id, 38, 0xBEEF));
    const network_failure = try validatePendingActivation(&manager, &supervisor, &storage, healthy_request, &ledger, 39);
    try std.testing.expect(network_failure.activation.rolled_back);
    try std.testing.expectEqual(immutable_base.HealthFailure.network, network_failure.activation.failure);
    try std.testing.expect(supervisor.markHealthy(network_service_id, 40));

    try manager.beginActivation(1, 41);
    try recordBootSuccess(&manager, 42);
    try std.testing.expect(supervisor.recordCrash(ui_service_id, 43, 0xFA17));
    const ui_failure = try validatePendingActivation(&manager, &supervisor, &storage, healthy_request, &ledger, 44);
    try std.testing.expect(ui_failure.activation.rolled_back);
    try std.testing.expectEqual(immutable_base.HealthFailure.ui, ui_failure.activation.failure);
    try std.testing.expect(supervisor.markHealthy(ui_service_id, 45));

    try manager.beginActivation(1, 46);
    try recordBootSuccess(&manager, 47);
    const success = try validatePendingActivation(&manager, &supervisor, &storage, healthy_request, &ledger, 48);
    try std.testing.expect(!success.activation.rolled_back);
    try std.testing.expectEqual(@as(?usize, 1), success.activation.active_slot);
    try std.testing.expect(manager.verifyActiveImage());
    try std.testing.expectEqual(@as(u64, 5), success.activation.rollback_generation);

    var export_buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=boot") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=core_service") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=storage") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=network") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "failure=ui") != null);
}
