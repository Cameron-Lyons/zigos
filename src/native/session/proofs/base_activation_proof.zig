//! Verification-kernel A/B base image rollback and post-activation health proofs.
//! Only the verification service graph imports this module.
const builtin = @import("builtin");
const std = @import("std");
const native_util = @import("../../core/util.zig");
const boot_markers = @import("../../../kernel/boot/markers.zig");
const config = @import("../../../kernel/config.zig");
const crypto_hash = @import("../../core/crypto_hash.zig");
const base_boot_selector = @import("../../platform/base_boot_selector.zig");
const compositor_session = @import("../../platform/compositor_session.zig");
const immutable_base = @import("../../platform/immutable_base.zig");
const principal = @import("../../core/principal.zig");
const service_graph_builder_mod = @import("../service_graph_builder.zig");
const signing = @import("../../core/signing.zig");
const sync_service = @import("../../sync/sync_service.zig");
const transient_sync_service = @import("../../sync/transient_service.zig");
const trust_boot = @import("../trust_boot.zig");
const update_health = @import("../../platform/update_health.zig");

const BASE_SELECTOR_LINE_BUFFER_BYTES: usize = 128;
const BASE_IMAGE_DIGEST_OFFSET: usize = 0;
const POLICY_DIGEST_OFFSET: usize = crypto_hash.digest_bytes;
const BASE_IMAGE_SLOT_INDEX_OFFSET: usize = crypto_hash.digest_bytes * 2;
const BASE_IMAGE_SLOT_PAYLOAD_BYTES: usize = BASE_IMAGE_SLOT_INDEX_OFFSET + @sizeOf(u64);

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const console = if (builtin.target.os.tag == .freestanding)
    @import("../../../kernel/utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

pub fn proveAbImageRollback(
    trust: *trust_boot.TrustBoot,
    graph: *const service_graph_builder_mod.ServiceGraph,
) bool {
    const state_signer = signing.SignerIdentity{
        .label = "zigos-base-state",
        .seed = signing.seedFromByte(0xA1),
    };
    const image_signer = signing.SignerIdentity{
        .label = "zigos-base-image",
        .seed = signing.seedFromByte(0xA2),
    };

    var base_manager = immutable_base.Manager.init(
        &trust.native_store.storage_service_instance,
        graph.state.ids.package_service,
        state_signer,
    ) catch return false;

    var selector = base_boot_selector.Selector.init();
    const loaded_selector_before_boot = loadPersistentBaseSelector(&selector);
    const cold_reboot_selector_verified = loaded_selector_before_boot and
        selector.activeSlotIndex() != null and
        selector.activeSlotIndex().? == 0 and
        selector.coldRebootVerified(0, selector.activation_generation);

    const stable_payload = baseImageSlotPayload(trust, graph, 0);
    _ = base_manager.stageImage(0, "stable-a", &stable_payload, image_signer, 70) catch return false;
    const stable = base_manager.activate(0, .{}, 71) catch return false;
    if (stable.rolled_back or stable.active_slot == null or stable.active_slot.? != 0) return false;

    _ = selector.bindStable(&base_manager, base_manager.selectVerifiedBootImage() catch return false, 71) catch return false;
    if (!persistPersistentBaseSelector(&selector)) return false;

    const candidate_payload = baseImageSlotPayload(trust, graph, 1);
    _ = base_manager.stageImage(1, "stable-b", &candidate_payload, image_signer, 72) catch return false;
    base_manager.beginActivation(1, 73) catch return false;
    const candidate = base_manager.selectVerifiedBootImage() catch return false;
    _ = selector.stageCandidate(&base_manager, candidate, 73) catch return false;
    const boot_candidate = selector.selectBootCandidate(&base_manager) catch return false;
    if (boot_candidate.slot_index != 1) return false;
    if (!persistPersistentBaseSelector(&selector)) return false;

    if (config.smokeFaultIs(.rollback_slot_failure)) {
        base_manager.slots[0].measurement[0] ^= 0xA5;
        const rejected_rollback = base_manager.finalizeActivation(.{ .network_ok = false }, 74) catch return false;
        const rejected_selector = selector.finalizeBoot(.{ .network_ok = false }, false, 74) catch return false;
        if (!rejected_rollback.rolled_back or rejected_rollback.active_slot == null or rejected_rollback.active_slot.? != 0) return false;
        if (!rejected_selector.rolled_back or rejected_selector.active_slot == null or rejected_selector.active_slot.? != 0) return false;
        if (base_manager.verifyActiveImage()) return false;
        if (base_manager.selectVerifiedBootImage()) |_| {
            return false;
        } else |err| {
            if (err != error.ImageVerificationFailed) return false;
        }
        common.printBootMarker(boot_markers.platform_base_selector_rollback_slot_failure_rejected);
        return false;
    }

    const rolled_back = base_manager.finalizeActivation(.{ .network_ok = false }, 74) catch return false;
    const selector_rollback = selector.finalizeBoot(.{ .network_ok = false }, false, 74) catch return false;
    if (!rolled_back.rolled_back) return false;
    if (rolled_back.active_slot == null or rolled_back.active_slot.? != 0) return false;
    if (!selector_rollback.rolled_back or selector_rollback.active_slot == null or selector_rollback.active_slot.? != 0) return false;
    if (selector_rollback.activation_generation != rolled_back.activation_generation) return false;
    if (selector_rollback.rollback_generation != rolled_back.rollback_generation) return false;
    if (!persistPersistentBaseSelector(&selector)) return false;
    if (!base_manager.verifyActiveImage()) return false;
    const selected = base_manager.selectVerifiedBootImage() catch return false;
    const selector_selected = selector.activeSelection() orelse return false;
    if (selected.slot_index != 0 or selected.activation_generation != rolled_back.activation_generation) return false;
    if (selected.rollback_generation != rolled_back.rollback_generation) return false;
    if (!baseSelectionMatches(selected, selector_selected)) return false;

    common.printBootMarker(boot_markers.platform_immutable_base_active);
    common.printBootMarker(boot_markers.platform_immutable_base_boot_selection);
    common.printBootMarker(boot_markers.platform_activation_rollback_ok);
    common.printBootMarker(boot_markers.platform_ab_image_rollback_ok);
    common.printBootMarker(boot_markers.platform_base_selector_active_slot_verified);
    common.printBootMarker(boot_markers.platform_base_selector_rollback_before_service);
    if (cold_reboot_selector_verified) {
        common.printBootMarker(boot_markers.platform_base_selector_cold_reboot_slot_verified);
    }
    printBaseSelectorActiveSlot(selected);
    return true;
}

pub fn provePostActivationHealthChecks(
    trust: *trust_boot.TrustBoot,
    graph: *const service_graph_builder_mod.ServiceGraph,
) bool {
    const owner = graph.state.ids.package_service;
    const state_signer = signing.SignerIdentity{
        .label = "zigos-base-state",
        .seed = signing.seedFromByte(0xA1),
    };
    const image_signer = signing.SignerIdentity{
        .label = "zigos-base-image",
        .seed = signing.seedFromByte(0xA2),
    };

    var manager = immutable_base.Manager.init(
        &trust.native_store.storage_service_instance,
        owner,
        state_signer,
    ) catch return false;
    const workspace_id = manager.workspace_id;
    const sync_record = trust.supervisor.findByClass(.sync_replication) orelse return false;
    const sync_resident_state = trust.native_store.syncResidentStatePtr() catch return false;
    var sync_instance_storage: transient_sync_service.Instance = undefined;
    sync_instance_storage.initInto(
        sync_record.id,
        graph.service_bindings.bindingFor(.sync_replication).task_id,
        sync_record.owner,
        &trust.native_store.storage_service_instance,
        sync_resident_state,
    ) catch return false;
    defer sync_instance_storage.deinit();
    const sync_instance = sync_instance_storage.ptr();
    const network_probe = seedHealthNetworkProbe(trust, sync_instance, workspace_id, 81) catch return false;
    const compositor_task = trust.runtime.find(graph.service_bindings.bindingFor(.compositor_ui_session).task_id) orelse return false;
    var compositor_snapshot: compositor_session.SessionSnapshot = undefined;
    trust.compositor.snapshotInto(&compositor_snapshot);
    defer trust.compositor.restoreFromSnapshot(&compositor_snapshot) catch |err|
        native_util.impossibleByInvariantError("activation health restores its retained compositor snapshot", err);
    _ = trust.compositor.openTaskView(compositor_task, "Post-Activation Health") catch return false;

    const policy_service_id = (trust.supervisor.findByClass(.policy_mediation) orelse return false).id;
    const package_service_id = (trust.supervisor.findByClass(.package_install_update) orelse return false).id;
    const sync_service_id = sync_record.id;
    const network_service_id = (trust.supervisor.findByClass(.network_stack) orelse return false).id;
    const ui_service_id = (trust.supervisor.findByClass(.compositor_ui_session) orelse return false).id;
    const core_service_ids = [_]u64{ policy_service_id, package_service_id, sync_service_id };
    const healthy_request = update_health.CheckRequest{
        .core_service_ids = core_service_ids[0..],
        .storage_workspace_id = workspace_id,
        .storage_probe_path = "state/activation",
        .network_service_id = network_service_id,
        .ui_service_id = ui_service_id,
        .network_probe = network_probe,
        .ui_probe = .{ .session = trust.compositor },
        .require_service_path_probes = true,
    };

    const stable_payload = baseImageSlotPayload(trust, graph, 0);
    _ = manager.stageImage(0, "stable-a", &stable_payload, image_signer, 82) catch return false;
    manager.beginActivation(0, 83) catch return false;
    update_health.recordBootSuccess(&manager, 84) catch return false;
    const first_activation = update_health.validatePendingActivation(
        &manager,
        trust.supervisor,
        &trust.native_store.storage_service_instance,
        healthy_request,
        null,
        85,
    ) catch return false;
    if (first_activation.activation.rolled_back or first_activation.activation.active_slot == null or first_activation.activation.active_slot.? != 0) return false;

    const candidate_payload = baseImageSlotPayload(trust, graph, 1);
    _ = manager.stageImage(1, "stable-b", &candidate_payload, image_signer, 86) catch return false;

    const FailureCase = struct {
        expected: immutable_base.HealthFailure,
        request: update_health.CheckRequest,
        crash_service_id: ?u64 = null,
        marker: []const u8,
    };
    const cases = [_]FailureCase{
        .{
            .expected = .boot,
            .request = healthy_request,
            .marker = boot_markers.platform_health_checks_boot_rollback,
        },
        .{
            .expected = .core_service,
            .request = healthy_request,
            .crash_service_id = sync_service_id,
            .marker = boot_markers.platform_health_checks_core_rollback,
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
                .ui_probe = .{ .session = trust.compositor },
                .require_service_path_probes = true,
            },
            .marker = boot_markers.platform_health_checks_storage_rollback,
        },
        .{
            .expected = .network,
            .request = .{
                .core_service_ids = core_service_ids[0..],
                .storage_workspace_id = workspace_id,
                .storage_probe_path = "state/activation",
                .network_service_id = network_service_id,
                .ui_service_id = ui_service_id,
                .ui_probe = .{ .session = trust.compositor },
                .require_service_path_probes = true,
            },
            .marker = boot_markers.platform_health_checks_network_rollback,
        },
        .{
            .expected = .ui,
            .request = .{
                .core_service_ids = core_service_ids[0..],
                .storage_workspace_id = workspace_id,
                .storage_probe_path = "state/activation",
                .network_service_id = network_service_id,
                .ui_service_id = ui_service_id,
                .network_probe = network_probe,
                .require_service_path_probes = true,
            },
            .marker = boot_markers.platform_health_checks_ui_rollback,
        },
    };

    for (cases, 0..) |case, index| {
        const tick_base = 90 + @as(u64, @intCast(index * 10));
        manager.beginActivation(1, tick_base) catch return false;
        if (case.expected != .boot) {
            update_health.recordBootSuccess(&manager, tick_base + 1) catch return false;
        }
        if (case.crash_service_id) |service_id| {
            if (!trust.supervisor.recordCrash(service_id, tick_base + 2, 0xB007_1000 + @as(u32, @intCast(index)))) return false;
        }
        const result = update_health.validatePendingActivation(
            &manager,
            trust.supervisor,
            &trust.native_store.storage_service_instance,
            case.request,
            null,
            tick_base + 3,
        ) catch return false;
        if (!result.activation.rolled_back) return false;
        if (result.activation.failure != case.expected) return false;
        if (result.activation.active_slot == null or result.activation.active_slot.? != 0) return false;
        if (case.crash_service_id) |service_id| {
            if (!trust.supervisor.markHealthy(service_id)) return false;
        }
        common.printBootMarker(case.marker);
    }

    manager.beginActivation(1, 150) catch return false;
    update_health.recordBootSuccess(&manager, 151) catch return false;
    const success = update_health.validatePendingActivation(
        &manager,
        trust.supervisor,
        &trust.native_store.storage_service_instance,
        healthy_request,
        null,
        152,
    ) catch return false;
    if (success.activation.rolled_back or success.activation.active_slot == null or success.activation.active_slot.? != 1) return false;
    if (!success.evaluation.report.isHealthy()) return false;
    if (!manager.verifyActiveImage()) return false;
    common.printBootMarker(boot_markers.platform_health_checks_promote_ok);

    manager.beginActivation(0, 153) catch return false;
    update_health.recordBootSuccess(&manager, 154) catch return false;
    const restored = update_health.validatePendingActivation(
        &manager,
        trust.supervisor,
        &trust.native_store.storage_service_instance,
        healthy_request,
        null,
        155,
    ) catch return false;
    if (restored.activation.rolled_back or restored.activation.active_slot == null or restored.activation.active_slot.? != 0) return false;
    return true;
}

fn baseImageSlotPayload(
    trust: *const trust_boot.TrustBoot,
    graph: *const service_graph_builder_mod.ServiceGraph,
    slot_index: u8,
) [BASE_IMAGE_SLOT_PAYLOAD_BYTES]u8 {
    const base_digest = trust.productionBaseImageManifestDigest(graph);
    const policy_digest = trust.productionPolicyDigest(graph);
    var payload = @as([BASE_IMAGE_SLOT_PAYLOAD_BYTES]u8, @splat(0));
    @memcpy(payload[BASE_IMAGE_DIGEST_OFFSET..][0..crypto_hash.digest_bytes], &base_digest);
    @memcpy(payload[POLICY_DIGEST_OFFSET..][0..crypto_hash.digest_bytes], &policy_digest);
    std.mem.writeInt(u64, payload[BASE_IMAGE_SLOT_INDEX_OFFSET..][0..@sizeOf(u64)], slot_index, .little);
    return payload;
}

fn seedHealthNetworkProbe(
    trust: *trust_boot.TrustBoot,
    sync: *sync_service.Service,
    workspace_id: u64,
    tick_base: u64,
) !update_health.NetworkProbe {
    const user = principal.PrincipalId{ .kind = .user, .serial = 82_201 };
    const source_device = principal.PrincipalId{ .kind = .device, .serial = 82_202 };
    const target_device = principal.PrincipalId{ .kind = .device, .serial = 82_203 };
    const user_signer = signing.SignerIdentity{
        .label = "zigos-health-user",
        .seed = signing.seedFromByte(0xB4),
    };
    const source_signer = signing.SignerIdentity{
        .label = "zigos-health-source",
        .seed = signing.seedFromByte(0xB5),
    };
    const target_signer = signing.SignerIdentity{
        .label = "zigos-health-target",
        .seed = signing.seedFromByte(0xB6),
    };

    const authority_capability = try sync_service.mintEndpointConnectAuthority(trust.capability_table, sync, tick_base, tick_base + 1_000);
    var port = sync_service.SyncPort.init(sync, trust.capability_table);
    const authority = sync_service.authorityContext(sync, authority_capability, tick_base);

    _ = try port.ensureUserRoot(authority, user, "production-health", user_signer);
    _ = try port.enrollTrustedDevice(authority, user, source_device, "source", user_signer, source_signer, tick_base + 1);
    _ = try port.enrollTrustedDevice(authority, user, target_device, "target", user_signer, target_signer, tick_base + 2);

    const local_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "production-health-local",
        .mode = .local_network,
    });
    const overlay_policy = try port.createNetworkPolicy(authority, .{
        .owner = sync.owner,
        .workspace_id = workspace_id,
        .label = "production-health-overlay",
        .mode = .named_service_identity,
        .target = "overlay.production.health",
    });
    _ = try port.configureWorkspacePolicy(authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
        .overlay_policy_id = overlay_policy.id,
    });
    _ = try port.configureOverlay(authority, workspace_id, source_device, "overlay.production.health", true);

    return .{
        .sync = sync,
        .capability_table = trust.capability_table,
        .authority = authority,
        .workspace_id = workspace_id,
        .source_device = source_device,
        .target_device = target_device,
        .tick = tick_base + 3,
    };
}
fn loadPersistentBaseSelector(selector: *base_boot_selector.Selector) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    selector.loadFromRootVolume() catch return false;
    return true;
}

fn persistPersistentBaseSelector(selector: *const base_boot_selector.Selector) bool {
    if (builtin.target.os.tag != .freestanding) return true;
    selector.persistToRootVolume() catch return false;
    return true;
}

fn baseSelectionMatches(
    left: immutable_base.BootSelection,
    right: immutable_base.BootSelection,
) bool {
    return left.slot_index == right.slot_index and
        left.object_id == right.object_id and
        left.version_id == right.version_id and
        left.activation_generation == right.activation_generation and
        left.rollback_generation == right.rollback_generation and
        std.mem.eql(u8, &left.measurement, &right.measurement) and
        left.signer_len == right.signer_len and
        std.mem.eql(u8, left.signerSlice(), right.signerSlice());
}

fn printBaseSelectorActiveSlot(selection: immutable_base.BootSelection) void {
    var buffer: [BASE_SELECTOR_LINE_BUFFER_BYTES]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        "{s}{d} generation={d} rollback={d}\n",
        .{
            base_boot_selector.active_slot_line_prefix,
            selection.slot_index,
            selection.activation_generation,
            selection.rollback_generation,
        },
    ) catch return;
    console.print(line);
}
