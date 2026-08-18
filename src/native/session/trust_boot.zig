const builtin = @import("builtin");
const native_util = @import("../core/util.zig");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const driver_service = @import("../drivers/driver_service.zig");
const base_boot_selector = @import("../platform/base_boot_selector.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const immutable_base = @import("../platform/immutable_base.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const measured_boot_console = @import("../platform/measured_boot_console.zig");
const native_service_registry = @import("../services/service_registry.zig");
const native_store_mount = @import("native_store_mount.zig");
const principal = @import("../core/principal.zig");
const service_catalog = @import("service_catalog.zig");
const service_graph_builder_mod = @import("service_graph_builder.zig");
const session_bootstrap = @import("session_bootstrap.zig");
const session_contexts = @import("session_manager_contexts.zig");
const signing = @import("../core/signing.zig");
const supervisor_mod = @import("supervisor.zig");
const sync_service = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const update_health = @import("../platform/update_health.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const volume_backend = @import("../storage/volume/backend.zig");

const build_bootloader_measurement_label = "multiboot:zigos_native";
const BASE_SELECTOR_LINE_BUFFER_BYTES: usize = 128;
const BASE_IMAGE_DIGEST_OFFSET: usize = 0;
const POLICY_DIGEST_OFFSET: usize = crypto_hash.digest_bytes;
const BASE_IMAGE_SLOT_INDEX_OFFSET: usize = crypto_hash.digest_bytes * 2;
const BASE_IMAGE_SLOT_PAYLOAD_BYTES: usize = BASE_IMAGE_SLOT_INDEX_OFFSET + @sizeOf(u64);
const critical_service_classes = [_]service_catalog.ServiceClass{
    .policy_mediation,
    .storage_object,
    .compositor_ui_session,
    .network_stack,
};

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const console = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

pub const TrustBoot = struct {
    runtime: *task_runtime.Runtime,
    userspace_catalog: *userspace_loader.Catalog,
    capability_table: *capability.CapabilityTable,
    compositor: *compositor_session.Session,
    service_directory: *native_service_registry.Service,
    supervisor: *supervisor_mod.Supervisor,
    driver_directory: *driver_service.Directory,
    native_store: *native_store_mount.NativeStoreMount,

    pub fn init(
        runtime_context: *session_contexts.RuntimeContext,
        kernel_context: *session_contexts.KernelContext,
        compositor: *compositor_session.Session,
        graph_builder: *service_graph_builder_mod.Builder,
        native_store: *native_store_mount.NativeStoreMount,
    ) TrustBoot {
        const capability_table = kernel_context.capabilityTable() orelse
            native_util.impossibleByInvariant("trust boot construction follows capability-table allocation");
        return .{
            .runtime = &runtime_context.runtime,
            .userspace_catalog = &runtime_context.userspace_catalog,
            .capability_table = capability_table,
            .compositor = compositor,
            .service_directory = &graph_builder.service_directory,
            .supervisor = &graph_builder.supervisor,
            .driver_directory = &graph_builder.driver_directory,
            .native_store = native_store,
        };
    }

    pub fn verifyProductionArtifactManifest(
        self: *const TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
    ) bool {
        const artifact_manifest = self.buildProductionArtifactManifest(graph) catch return false;
        if (builtin.target.os.tag == .freestanding) {
            if (!self.verifyGeneratedProductionArtifactManifest(true)) return false;
            common.printBootMarker(boot_markers.platform_artifact_manifest_verified);
            return true;
        }
        const signed_manifest = signProductionArtifactManifest(artifact_manifest) catch return false;
        if (!measured_boot.verifySignedArtifactManifest(
            &signed_manifest,
            measured_boot.production_artifact_manifest_signer,
        )) return false;
        common.printBootMarker(boot_markers.platform_artifact_manifest_verified);
        return true;
    }

    pub fn proveProductionAbImageRollback(
        self: *TrustBoot,
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
            &self.native_store.storage_service_instance,
            graph.state.ids.package_service,
            state_signer,
        ) catch return false;

        var selector = base_boot_selector.Selector.init();
        const loaded_selector_before_boot = loadPersistentBaseSelector(&selector);
        const cold_reboot_selector_verified = loaded_selector_before_boot and
            selector.activeSlotIndex() != null and
            selector.activeSlotIndex().? == 0 and
            selector.coldRebootVerified(0, selector.activation_generation);

        const stable_payload = self.productionBaseImageSlotPayload(graph, 0);
        _ = base_manager.stageImage(0, "stable-a", &stable_payload, image_signer, 70) catch return false;
        const stable = base_manager.activate(0, .{}, 71) catch return false;
        if (stable.rolled_back or stable.active_slot == null or stable.active_slot.? != 0) return false;

        _ = selector.bindStable(&base_manager, base_manager.selectVerifiedBootImage() catch return false, 71) catch return false;
        if (!persistPersistentBaseSelector(&selector)) return false;

        const candidate_payload = self.productionBaseImageSlotPayload(graph, 1);
        _ = base_manager.stageImage(1, "stable-b", &candidate_payload, image_signer, 72) catch return false;
        base_manager.beginActivation(1, 73) catch return false;
        const candidate = base_manager.selectVerifiedBootImage() catch return false;
        _ = selector.stageCandidate(&base_manager, candidate, 73) catch return false;
        const boot_candidate = selector.selectBootCandidate(&base_manager) catch return false;
        if (boot_candidate.slot_index != 1) return false;
        if (!persistPersistentBaseSelector(&selector)) return false;

        if (smokeFaultModeIs("rollback_slot_failure")) {
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

    pub fn proveProductionPostActivationHealthChecks(
        self: *TrustBoot,
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
            &self.native_store.storage_service_instance,
            owner,
            state_signer,
        ) catch return false;
        const workspace_id = manager.workspace_id;
        const sync_record = self.supervisor.findByClass(.sync_replication) orelse return false;
        const sync_resident_state = self.native_store.syncResidentStatePtr() catch return false;
        var sync_instance = sync_service.Service.initWithStorage(
            sync_record.id,
            graph.service_bindings.bindingFor(.sync_replication).task_id,
            sync_record.owner,
            &self.native_store.storage_service_instance,
            sync_resident_state,
        ) catch return false;
        const network_probe = self.seedProductionHealthNetworkProbe(&sync_instance, workspace_id, 81) catch return false;
        const compositor_task = self.runtime.find(graph.service_bindings.bindingFor(.compositor_ui_session).task_id) orelse return false;
        const compositor_snapshot = self.compositor.snapshot();
        defer self.compositor.restore(compositor_snapshot) catch |err|
            native_util.impossibleByInvariantError("activation health restores its retained compositor snapshot", err);
        _ = self.compositor.openTaskView(compositor_task, "Post-Activation Health") catch return false;

        const policy_service_id = (self.supervisor.findByClass(.policy_mediation) orelse return false).id;
        const package_service_id = (self.supervisor.findByClass(.package_install_update) orelse return false).id;
        const sync_service_id = sync_record.id;
        const network_service_id = (self.supervisor.findByClass(.network_stack) orelse return false).id;
        const ui_service_id = (self.supervisor.findByClass(.compositor_ui_session) orelse return false).id;
        const core_service_ids = [_]u64{ policy_service_id, package_service_id, sync_service_id };
        const healthy_request = update_health.CheckRequest{
            .core_service_ids = core_service_ids[0..],
            .storage_workspace_id = workspace_id,
            .storage_probe_path = "state/activation",
            .network_service_id = network_service_id,
            .ui_service_id = ui_service_id,
            .network_probe = network_probe,
            .ui_probe = .{ .session = self.compositor },
            .require_service_path_probes = true,
        };

        const stable_payload = self.productionBaseImageSlotPayload(graph, 0);
        _ = manager.stageImage(0, "stable-a", &stable_payload, image_signer, 82) catch return false;
        manager.beginActivation(0, 83) catch return false;
        update_health.recordBootSuccess(&manager, 84) catch return false;
        const first_activation = update_health.validatePendingActivation(
            &manager,
            self.supervisor,
            &self.native_store.storage_service_instance,
            healthy_request,
            null,
            85,
        ) catch return false;
        if (first_activation.activation.rolled_back or first_activation.activation.active_slot == null or first_activation.activation.active_slot.? != 0) return false;

        const candidate_payload = self.productionBaseImageSlotPayload(graph, 1);
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
                    .ui_probe = .{ .session = self.compositor },
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
                    .ui_probe = .{ .session = self.compositor },
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
                if (!self.supervisor.recordCrash(service_id, tick_base + 2, 0xB007_1000 + @as(u32, @intCast(index)))) return false;
            }
            const result = update_health.validatePendingActivation(
                &manager,
                self.supervisor,
                &self.native_store.storage_service_instance,
                case.request,
                null,
                tick_base + 3,
            ) catch return false;
            if (!result.activation.rolled_back) return false;
            if (result.activation.failure != case.expected) return false;
            if (result.activation.active_slot == null or result.activation.active_slot.? != 0) return false;
            if (case.crash_service_id) |service_id| {
                if (!self.supervisor.markHealthy(service_id, tick_base + 4)) return false;
            }
            common.printBootMarker(case.marker);
        }

        manager.beginActivation(1, 150) catch return false;
        update_health.recordBootSuccess(&manager, 151) catch return false;
        const success = update_health.validatePendingActivation(
            &manager,
            self.supervisor,
            &self.native_store.storage_service_instance,
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
            self.supervisor,
            &self.native_store.storage_service_instance,
            healthy_request,
            null,
            155,
        ) catch return false;
        if (restored.activation.rolled_back or restored.activation.active_slot == null or restored.activation.active_slot.? != 0) return false;
        return true;
    }

    pub fn recordProductionMeasuredBoot(
        self: *TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
    ) bool {
        const artifact_manifest = self.buildProductionArtifactManifest(graph) catch return false;
        const signed_manifest = signProductionArtifactManifest(artifact_manifest) catch return false;
        if (!measured_boot.verifySignedArtifactManifest(
            &signed_manifest,
            measured_boot.production_artifact_manifest_signer,
        )) return false;
        if (builtin.target.os.tag == .freestanding) {
            if (!self.verifyGeneratedProductionArtifactManifest(false)) return false;
        }

        var measured = measured_boot.Recorder.init();
        measured.begin(1);
        const kernel_digest = productionKernelMeasurementDigest() catch return false;
        const base_manifest_digest = self.productionBaseImageManifestDigest(graph);
        const policy_digest = self.productionPolicyDigest(graph);
        measured.add(.kernel, "bootloader+kernel-zigos-native", &kernel_digest) catch return false;
        measured.add(.base_image, "production-native-base", &base_manifest_digest) catch return false;
        measured.add(.policy, "production-policy-set", &policy_digest) catch return false;

        for (critical_service_classes) |class| {
            const service_record = self.supervisor.findByClass(class) orelse return false;
            const image = self.criticalServiceImage(service_record) orelse return false;
            measured.addCriticalServiceImage(service_record, image) catch return false;
        }
        measured.addDriverSet("production-driver-set", self.driver_directory) catch return false;

        var boot = measured.finalize();
        if (builtin.target.os.tag == .freestanding) {
            const handoff = measured_boot.BootloaderMeasurementHandoff.fromBootRecord(&boot) catch return false;
            if (smokeFaultModeIs("tampered_artifact_manifest")) {
                var tampered_manifest = signed_manifest;
                tampered_manifest.manifest.entries[0].digest[0] ^= 0x5A;
                if (measured_boot.verifyBootloaderMeasurementHandoff(
                    &handoff,
                    &tampered_manifest,
                    measured_boot.production_artifact_manifest_signer,
                )) |_| {
                    return false;
                } else |err| switch (err) {
                    error.UntrustedArtifactManifest, error.ManifestMismatch => {
                        common.printBootMarker(boot_markers.platform_artifact_manifest_tamper_rejected);
                        return false;
                    },
                    else => return false,
                }
            }
            if (directArtifactTamperFixture()) |fixture| {
                if (!rejectDirectArtifactTamper(&handoff, &signed_manifest, fixture.kind, fixture.marker)) return false;
                return false;
            }
            boot = measured_boot.verifyBootloaderMeasurementHandoff(
                &handoff,
                &signed_manifest,
                measured_boot.production_artifact_manifest_signer,
            ) catch return false;
            common.printBootMarker(boot_markers.platform_bootloader_handoff_verified);
        } else {
            measured_boot.verifyBootRecordAgainstManifest(
                &boot,
                &artifact_manifest,
                productionRootProvenance(),
            ) catch return false;
        }
        measured_boot_console.printMeasurementSummary(&boot);
        supportMeasuredBootShape(&boot);
        self.recordMeasurementComparison(&boot);
        return true;
    }

    fn verifyGeneratedProductionArtifactManifest(self: *const TrustBoot, print_markers: bool) bool {
        if (builtin.target.os.tag != .freestanding) return true;

        const root = @import("root");
        if (!@hasDecl(root, "production_artifact_manifest")) return false;
        const generated_manifest = measured_boot.buildArtifactManifestFromGenerated(root.production_artifact_manifest) catch return false;
        if (!measured_boot.verifyBuildArtifactManifest(&generated_manifest)) return false;

        const bootloader_source_digest = bootloaderSourceDigest() catch return false;
        if (!measured_boot.buildArtifactDigestMatches(
            &generated_manifest,
            .bootloader_source,
            buildBootloaderSourceLabel(),
            &bootloader_source_digest,
        )) return false;

        const bootloader_measurement_digest = bootloaderProvidedMeasurementDigest() catch return false;
        if (smokeFaultModeIs("tampered_bootloader_measurement")) {
            var tampered_measurement_digest = bootloader_measurement_digest;
            tampered_measurement_digest[0] ^= 0x7B;
            if (measured_boot.buildArtifactDigestMatches(
                &generated_manifest,
                .bootloader_measurement,
                build_bootloader_measurement_label,
                &tampered_measurement_digest,
            )) return false;
            common.printBootMarker(boot_markers.platform_bootloader_measurement_tamper_rejected);
            return false;
        }
        if (!measured_boot.buildArtifactDigestMatches(
            &generated_manifest,
            .bootloader_measurement,
            build_bootloader_measurement_label,
            &bootloader_measurement_digest,
        )) return false;

        var userspace_artifact_count: usize = 0;
        for (generated_manifest.entries[0..generated_manifest.entry_count]) |entry| {
            if (entry.kind != .userspace_image) continue;
            const image = self.userspace_catalog.findByBundleId(entry.labelSlice()) orelse return false;
            if (!image.bundle_signed) return false;
            if (!std.mem.eql(u8, &image.file_sha256, &entry.digest)) return false;
            userspace_artifact_count += 1;
        }
        if (userspace_artifact_count != self.userspace_catalog.imageCount()) return false;

        if (print_markers) {
            common.printBootMarker(boot_markers.platform_bootloader_measurement_provided);
            common.printBootMarker(boot_markers.platform_build_artifact_manifest_verified);
        }
        return true;
    }

    fn buildProductionArtifactManifest(
        self: *const TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
    ) !measured_boot.ArtifactManifest {
        var manifest_record = measured_boot.ArtifactManifest.init(1);
        const kernel_digest = try productionKernelMeasurementDigest();
        const base_manifest_digest = self.productionBaseImageManifestDigest(graph);
        const policy_digest = self.productionPolicyDigest(graph);
        try manifest_record.add(.kernel, "bootloader+kernel-zigos-native", &kernel_digest);
        try manifest_record.add(.base_image, "production-native-base", &base_manifest_digest);
        try manifest_record.add(.policy, "production-policy-set", &policy_digest);

        for (critical_service_classes) |class| {
            const service = self.supervisor.findByClass(class) orelse return error.MissingBootstrapLaunch;
            const bundle_id = service_catalog.bundleIdForServiceClass(service.class) orelse return error.MissingBootstrapLaunch;
            const image = self.userspace_catalog.findByBundleId(bundle_id) orelse return error.MissingUserspaceImage;
            try manifest_record.addCriticalServiceImage(service, image);
        }

        try manifest_record.addDriverSet("production-driver-set", self.driver_directory);
        return manifest_record;
    }

    fn productionBaseImageManifestDigest(
        self: *const TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
    ) crypto_hash.Digest {
        var hasher = crypto_hash.init();
        hashPrincipal(&hasher, "policy-authority", graph.state.ids.policy_authority);
        hashPrincipal(&hasher, "session-service", graph.state.ids.session_service);
        crypto_hash.updateInt(&hasher, "session-task-id", graph.state.session_task.id);
        crypto_hash.updateInt(&hasher, "review-service-task-id", graph.state.review_service_task.id);

        for (&self.supervisor.service_arena.slots) |*slot| {
            if (!slot.in_use) continue;
            hashServiceRecord(&hasher, &slot.service);
        }
        for (graph.service_bindings.bindings) |binding| {
            crypto_hash.updateInt(&hasher, "binding-task-id", binding.task_id);
            crypto_hash.updateInt(&hasher, "binding-endpoint-id", binding.endpoint_id);
        }
        for (&self.userspace_catalog.images.slots) |*slot| {
            if (!slot.in_use) continue;
            const image = &slot.image;
            crypto_hash.updateBytes(&hasher, "image-bundle", image.bundleIdSlice());
            crypto_hash.updateBytes(&hasher, "image-file-sha256", &image.file_sha256);
            crypto_hash.updateInt(&hasher, "image-id", image.id);
            crypto_hash.updateInt(&hasher, "image-byte-len", image.byte_len);
            crypto_hash.updateInt(&hasher, "image-contract-flags", image.contract_flags);
        }
        return crypto_hash.finalize(&hasher);
    }

    fn productionBaseImageSlotPayload(
        self: *const TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
        slot_index: u8,
    ) [BASE_IMAGE_SLOT_PAYLOAD_BYTES]u8 {
        const base_digest = self.productionBaseImageManifestDigest(graph);
        const policy_digest = self.productionPolicyDigest(graph);
        var payload = [_]u8{0} ** BASE_IMAGE_SLOT_PAYLOAD_BYTES;
        @memcpy(payload[BASE_IMAGE_DIGEST_OFFSET..][0..crypto_hash.digest_bytes], &base_digest);
        @memcpy(payload[POLICY_DIGEST_OFFSET..][0..crypto_hash.digest_bytes], &policy_digest);
        std.mem.writeInt(u64, payload[BASE_IMAGE_SLOT_INDEX_OFFSET..][0..@sizeOf(u64)], slot_index, .little);
        return payload;
    }

    fn productionPolicyDigest(
        self: *const TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
    ) crypto_hash.Digest {
        var hasher = crypto_hash.init();
        hashPrincipal(&hasher, "session-capability-holder", graph.state.session_capability.holder);
        hashCapability(&hasher, "session-capability", &graph.state.session_capability);
        hashCapability(&hasher, "policy-capability", &graph.state.policy_capability);

        for (&self.capability_table.slots.slots) |*slot| {
            if (!slot.in_use) continue;
            if (!capabilityTargetAffectsProductionPolicy(slot.capability.target.kind)) continue;
            hashCapability(&hasher, "capability", &slot.capability);
        }
        for (&self.service_directory.registry.bindings.slots) |*slot| {
            if (!slot.in_use) continue;
            const binding = &slot.binding;
            crypto_hash.updateInt(&hasher, "registry-service-id", binding.service_id);
            crypto_hash.updateInt(&hasher, "registry-owner-task-id", binding.owner_task_id);
            crypto_hash.updateInt(&hasher, "registry-endpoint-id", binding.endpoint_id);
            crypto_hash.updateInt(&hasher, "registry-endpoint-capability-id", binding.endpoint_capability_id);
            crypto_hash.updateInt(&hasher, "registry-interface-id", @intFromEnum(binding.interface_id));
            crypto_hash.updateBytes(&hasher, "registry-interface-name", binding.interface.name);
            crypto_hash.updateInt(&hasher, "registry-version-major", binding.interface.version_major);
            crypto_hash.updateInt(&hasher, "registry-version-minor", binding.interface.version_minor);
            crypto_hash.updateInt(&hasher, "registry-flags", binding.flags);
            crypto_hash.updateInt(&hasher, "registry-contract-hash", binding.typed_contract_hash);
        }
        return crypto_hash.finalize(&hasher);
    }

    fn criticalServiceImage(
        self: *TrustBoot,
        service_record: *const supervisor_mod.ServiceRecord,
    ) ?*const userspace_loader.ImageRecord {
        const bundle_id = service_catalog.bundleIdForServiceClass(service_record.class) orelse return null;
        return self.userspace_catalog.findByBundleId(bundle_id);
    }

    fn recordMeasurementComparison(self: *TrustBoot, boot: *const measured_boot.BootRecord) void {
        const measurement_signer = signing.SignerIdentity{
            .label = "zigos-measured-boot-state",
            .seed = signing.seedFromByte(0xA6),
        };
        const direct_previous = loadDirectMeasuredBootSummary(self.native_store.storage_service_instance.service_id);
        var journal = measured_boot.MeasurementJournal.init(
            &self.native_store.storage_service_instance,
            session_bootstrap.principals().package_service,
            measurement_signer,
        ) catch |err| native_util.bootProofFailure("trust boot", err);
        var comparison = journal.record(boot.*, 130) catch |err| native_util.bootProofFailure("trust boot", err);
        const current_summary = measured_boot.BootSummary.fromRecord(boot);
        if (comparison.previous == null) {
            if (direct_previous) |previous| {
                comparison.previous = previous;
                comparison.same_root_digest = std.mem.eql(u8, &previous.root_digest, &current_summary.root_digest);
                comparison.same_generation = previous.generation == current_summary.generation;
                comparison.same_record_shape = previous.record_count == current_summary.record_count and
                    std.mem.eql(u16, &previous.kind_counts, &current_summary.kind_counts);
            }
        }
        _ = storeDirectMeasuredBootSummary(self.native_store.storage_service_instance.service_id, current_summary);
        self.native_store.checkpoint();
        if (comparison.previous == null) {
            common.printBootMarker(boot_markers.platform_measured_boot_first);
            return;
        }
        if (comparison.same_root_digest) {
            common.printBootMarker(boot_markers.platform_measured_boot_same_root);
        }
        if (comparison.same_record_shape) {
            common.printBootMarker(boot_markers.platform_measured_boot_same_shape);
        }
    }

    fn seedProductionHealthNetworkProbe(
        self: *TrustBoot,
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

        const authority_capability = try sync_service.mintEndpointConnectAuthority(self.capability_table, sync, tick_base, tick_base + 1_000);
        var port = sync_service.SyncPort.init(sync, self.capability_table);
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
            .capability_table = self.capability_table,
            .authority = authority,
            .workspace_id = workspace_id,
            .source_device = source_device,
            .target_device = target_device,
            .tick = tick_base + 3,
        };
    }
};

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

fn productionKernelMeasurementDigest() !crypto_hash.Digest {
    var hasher = crypto_hash.init();
    const bootloader_digest = try bootloaderProvidedMeasurementDigest();
    const kernel_digest = try kernelImageDigest();
    crypto_hash.updateBytes(&hasher, "bootloader-measurement-digest", &bootloader_digest);
    crypto_hash.updateBytes(&hasher, "kernel-image-digest", &kernel_digest);
    return crypto_hash.finalize(&hasher);
}

fn productionRootProvenance() measured_boot.RootProvenance {
    if (builtin.target.os.tag == .freestanding) return .bootloader_provided;
    return .emulator_provided;
}

fn bootloaderProvidedMeasurementDigest() !crypto_hash.Digest {
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (@hasDecl(root, "bootloaderMeasurementDigest")) {
            return root.bootloaderMeasurementDigest();
        }
        return error.MissingBootloaderMeasurement;
    }
    return emulatorProvidedBootloaderMeasurementDigest();
}

fn bootloaderSourceDigest() !crypto_hash.Digest {
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (@hasDecl(root, "bootloaderSourceDigest")) {
            return root.bootloaderSourceDigest();
        }
        return error.MissingBootloaderSourceMeasurement;
    }
    return emulatorProvidedBootloaderSourceDigest();
}

fn kernelImageDigest() !crypto_hash.Digest {
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (@hasDecl(root, "kernelImageDigest")) {
            return root.kernelImageDigest();
        }
        return error.MissingKernelMeasurement;
    }
    return emulatorProvidedKernelImageDigest();
}

fn emulatorProvidedBootloaderSourceDigest() crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "measurement-source", "host-emulator-bootloader-source");
    crypto_hash.updateBytes(&hasher, "entry", buildBootloaderSourceLabel());
    return crypto_hash.finalize(&hasher);
}

fn emulatorProvidedBootloaderMeasurementDigest() crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "measurement-source", "host-emulator-bootloader-measurement");
    crypto_hash.updateBytes(&hasher, "bootloader", "multiboot");
    crypto_hash.updateBytes(&hasher, "entry", buildBootloaderSourceLabel());
    return crypto_hash.finalize(&hasher);
}

fn buildBootloaderSourceLabel() []const u8 {
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (@hasDecl(root, "bootloaderSourcePath")) return root.bootloaderSourcePath();
    }
    return "src/boot/boot_x86_64.S";
}

fn emulatorProvidedKernelImageDigest() crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "measurement-source", "host-emulator-kernel-image");
    crypto_hash.updateBytes(&hasher, "kernel", "kernel-zigos-native.elf");
    crypto_hash.updateBytes(&hasher, "profile", "zigos_native");
    return crypto_hash.finalize(&hasher);
}

fn hashPrincipal(hasher: *crypto_hash.Hasher, tag: []const u8, id: principal.PrincipalId) void {
    crypto_hash.updateBytes(hasher, "principal-tag", tag);
    crypto_hash.updateEnum(hasher, "principal-kind", id.kind);
    crypto_hash.updateInt(hasher, "principal-serial", id.serial);
}

fn hashServiceRecord(hasher: *crypto_hash.Hasher, service: *const supervisor_mod.ServiceRecord) void {
    crypto_hash.updateInt(hasher, "service-id", service.id);
    crypto_hash.updateInt(hasher, "service-isolation-domain-id", service.isolation_domain_id);
    crypto_hash.updateEnum(hasher, "service-class", service.class);
    crypto_hash.updateEnum(hasher, "service-boundary", service.boundary);
    hashPrincipal(hasher, "service-owner", service.owner);
    crypto_hash.updateBool(hasher, "service-restartable", service.restartable);
    crypto_hash.updateEnum(hasher, "service-network-privilege", service.network_privilege);
    crypto_hash.updateEnum(hasher, "service-storage-privilege", service.storage_privilege);
    crypto_hash.updateEnum(hasher, "service-ui-privilege", service.ui_privilege);
    if (service.driver_class) |driver_class| {
        crypto_hash.updateBool(hasher, "service-driver-class-present", true);
        crypto_hash.updateEnum(hasher, "service-driver-class", driver_class);
    } else {
        crypto_hash.updateBool(hasher, "service-driver-class-present", false);
    }
}

fn hashCapability(hasher: *crypto_hash.Hasher, tag: []const u8, cap: *const capability.Capability) void {
    crypto_hash.updateBytes(hasher, "capability-tag", tag);
    crypto_hash.updateInt(hasher, "capability-id", cap.id);
    hashPrincipal(hasher, "capability-holder", cap.holder);
    hashPrincipal(hasher, "capability-issuer", cap.issuer);
    crypto_hash.updateEnum(hasher, "capability-target-kind", cap.target.kind);
    crypto_hash.updateInt(hasher, "capability-target-id", cap.target.id);
    crypto_hash.updateInt(hasher, "capability-rights", cap.rights.toBits());
    crypto_hash.updateInt(hasher, "capability-scope-task", cap.scope.task_id orelse 0);
    crypto_hash.updateInt(hasher, "capability-scope-workspace", cap.scope.workspace_id orelse 0);
    crypto_hash.updateBool(hasher, "capability-scope-local-only", cap.scope.local_only);
    crypto_hash.updateBool(hasher, "capability-scope-broker-only", cap.scope.broker_only);
    // Issuance is runtime clock state, not part of the declared policy. Keeping
    // it out makes an equivalent cold boot measure the same authority graph.
    crypto_hash.updateInt(hasher, "capability-expires-at", cap.lease.expires_at_ticks);
    crypto_hash.updateBool(hasher, "capability-renewable", cap.lease.renewable);
    crypto_hash.updateInt(hasher, "capability-revocation-generation", cap.revocation_generation);
    crypto_hash.updateInt(hasher, "capability-policy-generation", cap.audit.policy_generation);
    crypto_hash.updateInt(hasher, "capability-source-task-id", cap.audit.source_task_id);
    crypto_hash.updateInt(hasher, "capability-broker-service-id", cap.audit.broker_service_id);
}

fn capabilityTargetAffectsProductionPolicy(kind: capability.CapabilityTargetKind) bool {
    return switch (kind) {
        .service, .device, .policy => true,
        .task, .endpoint, .shared_memory, .object, .workspace, .network_policy => false,
    };
}

test "production policy measurement excludes runtime resource grants" {
    try std.testing.expect(!capabilityTargetAffectsProductionPolicy(.task));
    try std.testing.expect(!capabilityTargetAffectsProductionPolicy(.endpoint));
    try std.testing.expect(!capabilityTargetAffectsProductionPolicy(.shared_memory));
    try std.testing.expect(!capabilityTargetAffectsProductionPolicy(.object));
    try std.testing.expect(!capabilityTargetAffectsProductionPolicy(.workspace));
    try std.testing.expect(!capabilityTargetAffectsProductionPolicy(.network_policy));
    try std.testing.expect(capabilityTargetAffectsProductionPolicy(.service));
    try std.testing.expect(capabilityTargetAffectsProductionPolicy(.device));
    try std.testing.expect(capabilityTargetAffectsProductionPolicy(.policy));
}

fn smokeFaultModeIs(comptime mode_name: []const u8) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    const config = @import("../../kernel/config.zig");
    return std.mem.eql(u8, @tagName(config.smokeFaultMode()), mode_name);
}

const ArtifactManifestSigningBackend = struct {
    seed: signing.Seed,

    fn sign(context: *anyopaque, key: signing.ReleaseRootKeyHandle, message: []const u8) ![signing.SIGNATURE_BYTES]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        const key_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(self.seed);
        if (!std.mem.eql(u8, &key.public_key, &key_pair.public_key.toBytes())) {
            return error.ReleaseKeyIdentityMismatch;
        }
        return (try key_pair.sign(message, null)).toBytes();
    }
};

fn signProductionArtifactManifest(
    artifact_manifest: measured_boot.ArtifactManifest,
) !measured_boot.SignedArtifactManifest {
    const identity = measured_boot.production_artifact_manifest_signer;
    var backend = ArtifactManifestSigningBackend{ .seed = identity.seed };
    var provider_impl = try signing.ExternalReleaseProvider.init(
        .{
            .name = "smoke-kms-artifact-manifest",
            .profile = .ed25519,
            .role = .production,
            .provider_boundary = .cloud_kms,
            .custody = .cloud_kms,
            .hardware_backed = true,
            .rotation_supported = true,
            .revocation_supported = true,
            .customer_verifiable = true,
            .verifier_protocol = .dsse_in_toto_slsa,
        },
        .{
            .key_id = "kms://zigos/smoke/artifact-manifest/1",
            .label = identity.label,
            .public_key = try signing.publicKey(identity),
            .generation = 1,
            .provider_boundary = .cloud_kms,
            .custody = .cloud_kms,
        },
        &backend,
        ArtifactManifestSigningBackend.sign,
    );
    return measured_boot.signArtifactManifestWithProvider(
        artifact_manifest,
        identity,
        provider_impl.provider(),
    );
}

const DirectArtifactTamperFixture = struct {
    mode_name: []const u8,
    kind: measured_boot.MeasurementKind,
    marker: []const u8,
};

const direct_artifact_tamper_fixtures = [_]DirectArtifactTamperFixture{
    .{
        .mode_name = "tampered_kernel",
        .kind = .kernel,
        .marker = boot_markers.platform_artifact_kernel_tamper_rejected,
    },
    .{
        .mode_name = "tampered_userspace_image",
        .kind = .critical_service,
        .marker = boot_markers.platform_artifact_userspace_image_tamper_rejected,
    },
    .{
        .mode_name = "tampered_policy",
        .kind = .policy,
        .marker = boot_markers.platform_artifact_policy_tamper_rejected,
    },
    .{
        .mode_name = "tampered_driver_set",
        .kind = .driver_set,
        .marker = boot_markers.platform_artifact_driver_set_tamper_rejected,
    },
};

fn directArtifactTamperFixture() ?DirectArtifactTamperFixture {
    inline for (direct_artifact_tamper_fixtures) |fixture| {
        if (smokeFaultModeIs(fixture.mode_name)) return fixture;
    }
    return null;
}

fn rejectDirectArtifactTamper(
    handoff: *const measured_boot.BootloaderMeasurementHandoff,
    signed_manifest: *const measured_boot.SignedArtifactManifest,
    kind: measured_boot.MeasurementKind,
    marker: []const u8,
) bool {
    var tampered_handoff = handoff.*;
    if (!tamperFirstHandoffRecord(&tampered_handoff, kind)) return false;

    if (measured_boot.verifyBootloaderMeasurementHandoff(
        &tampered_handoff,
        signed_manifest,
        measured_boot.production_artifact_manifest_signer,
    )) |_| {
        return false;
    } else |err| {
        switch (err) {
            error.ManifestMismatch,
            error.UntrustedArtifactManifest,
            error.UntrustedRootProvenance,
            => {},
            else => return false,
        }
        common.printBootMarker(marker);
        return true;
    }
}

fn tamperFirstHandoffRecord(
    handoff: *measured_boot.BootloaderMeasurementHandoff,
    kind: measured_boot.MeasurementKind,
) bool {
    for (handoff.records[0..handoff.record_count]) |*record| {
        if (record.kind != kind) continue;
        record.digest[0] ^= 0xA7;
        return true;
    }
    return false;
}

fn supportMeasuredBootShape(boot: *const measured_boot.BootRecord) void {
    if (boot.countKind(.kernel) == 1 and
        boot.countKind(.base_image) == 1 and
        boot.countKind(.critical_service) == critical_service_classes.len and
        boot.countKind(.policy) == 1 and
        boot.countKind(.driver_set) == 1 and
        boot.hasVerifiedRoot())
    {
        common.printBootMarker(boot_markers.platform_measured_boot_recorded);
        if (boot.isRemoteAttestable()) {
            common.printBootMarker(boot_markers.platform_measured_boot_verified_root);
        }
    }
}

const direct_measured_boot_lba: u64 = 1536;
const direct_measured_boot_magic = "ZMB2";
const direct_measured_boot_version: u16 = 1;
const direct_measured_boot_sector_size: usize = 512;
const direct_measured_boot_magic_offset: usize = 0;
const direct_measured_boot_version_offset: usize = 4;
const direct_measured_boot_record_count_offset: usize = 6;
const direct_measured_boot_generation_offset: usize = 8;
const direct_measured_boot_kind_counts_offset: usize = 16;
const direct_measured_boot_root_digest_offset: usize = 32;

fn loadDirectMeasuredBootSummary(storage_service_id: u64) ?measured_boot.BootSummary {
    if (builtin.target.os.tag != .freestanding) return null;
    var sector = [_]u8{0} ** direct_measured_boot_sector_size;
    if (!readDirectMeasuredBootSector(storage_service_id, &sector)) return null;
    if (!std.mem.eql(u8, sector[direct_measured_boot_magic_offset..][0..direct_measured_boot_magic.len], direct_measured_boot_magic)) return null;
    if (std.mem.readInt(u16, sector[direct_measured_boot_version_offset..][0..@sizeOf(u16)], .little) != direct_measured_boot_version) return null;

    var summary = measured_boot.BootSummary{
        .generation = std.mem.readInt(u64, sector[direct_measured_boot_generation_offset..][0..@sizeOf(u64)], .little),
        .record_count = std.mem.readInt(u16, sector[direct_measured_boot_record_count_offset..][0..@sizeOf(u16)], .little),
        .kind_counts = [_]u16{0} ** measured_boot.MEASUREMENT_KIND_COUNT,
        .root_digest = crypto_hash.zero_digest,
    };
    var offset: usize = direct_measured_boot_kind_counts_offset;
    for (&summary.kind_counts) |*count| {
        count.* = std.mem.readInt(u16, sector[offset..][0..2], .little);
        offset += 2;
    }
    @memcpy(&summary.root_digest, sector[direct_measured_boot_root_digest_offset..][0..summary.root_digest.len]);
    if (std.mem.allEqual(u8, &summary.root_digest, 0)) return null;
    return summary;
}

fn storeDirectMeasuredBootSummary(storage_service_id: u64, summary: measured_boot.BootSummary) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    var sector = [_]u8{0} ** direct_measured_boot_sector_size;
    @memcpy(sector[direct_measured_boot_magic_offset..][0..direct_measured_boot_magic.len], direct_measured_boot_magic);
    std.mem.writeInt(u16, sector[direct_measured_boot_version_offset..][0..@sizeOf(u16)], direct_measured_boot_version, .little);
    std.mem.writeInt(u16, sector[direct_measured_boot_record_count_offset..][0..@sizeOf(u16)], summary.record_count, .little);
    std.mem.writeInt(u64, sector[direct_measured_boot_generation_offset..][0..@sizeOf(u64)], summary.generation, .little);
    var offset: usize = direct_measured_boot_kind_counts_offset;
    for (summary.kind_counts) |count| {
        std.mem.writeInt(u16, sector[offset..][0..2], count, .little);
        offset += 2;
    }
    @memcpy(sector[direct_measured_boot_root_digest_offset..][0..summary.root_digest.len], &summary.root_digest);
    return writeDirectMeasuredBootSector(storage_service_id, &sector);
}

fn readDirectMeasuredBootSector(storage_service_id: u64, buffer: *[direct_measured_boot_sector_size]u8) bool {
    if (bootstrap_driver_port.activeStorageRead(storage_service_id, direct_measured_boot_lba, buffer[0..])) return true;

    const root = @import("root");
    if (!@hasDecl(root, "storage_volume")) return false;
    const root_volume = root.storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    return root_volume.attached_backend_read(direct_measured_boot_lba, buffer.ptr, buffer.len);
}

fn writeDirectMeasuredBootSector(storage_service_id: u64, buffer: *const [direct_measured_boot_sector_size]u8) bool {
    if (bootstrap_driver_port.activeStorageWrite(storage_service_id, direct_measured_boot_lba, buffer[0..])) {
        return bootstrap_driver_port.activeStorageFlush(storage_service_id);
    }

    const root = @import("root");
    if (!@hasDecl(root, "storage_volume")) return false;
    const root_volume = root.storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    return volume_backend.writeAttachedDurableRange(root_volume, direct_measured_boot_lba, buffer[0..]);
}
