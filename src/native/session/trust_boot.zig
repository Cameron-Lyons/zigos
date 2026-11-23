const builtin = @import("builtin");
const native_util = @import("../core/util.zig");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const config = @import("../../kernel/config.zig");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const driver_service = @import("../drivers/driver_service.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const measured_boot_console = @import("../platform/measured_boot_console.zig");
const native_service_registry = @import("../services/service_registry.zig");
const component_abi_schema = @import("../services/component_abi_schema.zig");
const native_store_mount = @import("native_store_mount.zig");
const principal = @import("../core/principal.zig");
const storage_volume = @import("../storage/storage_volume.zig");
const service_catalog = @import("service_catalog.zig");
const service_graph_builder_mod = @import("service_graph_builder.zig");
const session_bootstrap = @import("session_bootstrap.zig");
const session_contexts = @import("session_manager_contexts.zig");
const signing = @import("../core/signing.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const volume_backend = @import("../storage/volume/backend.zig");

const build_bootloader_measurement_label = "efi:zigos_native";
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
        const userspace_catalog = runtime_context.userspaceCatalog() orelse
            native_util.impossibleByInvariant("trust boot construction follows userspace-catalog allocation");
        return .{
            .runtime = runtime_context.taskRuntime() orelse
                native_util.impossibleByInvariant("trust boot follows task-runtime allocation"),
            .userspace_catalog = userspace_catalog,
            .capability_table = capability_table,
            .compositor = compositor,
            .service_directory = &graph_builder.service_directory,
            .supervisor = &graph_builder.supervisor,
            .driver_directory = &graph_builder.driver_directory,
            .native_store = native_store,
        };
    }

    pub fn verifyProductionArtifactManifest(self: *const TrustBoot) bool {
        if (!self.verifyGeneratedProductionArtifactManifest()) return false;
        common.printBootMarker(boot_markers.platform_artifact_manifest_verified);
        return true;
    }

    pub fn recordProductionMeasuredBoot(
        self: *TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
    ) bool {
        var measured = measured_boot.Recorder.init();
        measured.begin(1);
        var artifact_manifest = measured_boot.ArtifactManifest.init(1);
        self.measureProductionArtifacts(graph, &measured, &artifact_manifest) catch return false;

        const recorded = measured.finalize();
        const handoff = measured_boot.MeasurementSnapshot.fromBootRecord(&recorded) catch return false;
        if (config.smokeFaultIs(.tampered_artifact_manifest)) {
            var tampered_manifest = artifact_manifest;
            tampered_manifest.entries[0].digest[0] ^= 0x5A;
            if (measured_boot.verifyMeasurementSnapshot(
                &handoff,
                &tampered_manifest,
                productionRootProvenance(),
            )) |_| {
                return false;
            } else |err| switch (err) {
                error.ManifestMismatch => {
                    common.printBootMarker(boot_markers.platform_artifact_manifest_tamper_rejected);
                    return false;
                },
                else => return false,
            }
        }
        if (directArtifactTamperFixture()) |fixture| {
            rejectDirectArtifactTamper(&handoff, &artifact_manifest, fixture.kind, fixture.marker);
            return false;
        }
        const boot = measured_boot.verifyMeasurementSnapshot(
            &handoff,
            &artifact_manifest,
            productionRootProvenance(),
        ) catch return false;
        common.printBootMarker(boot_markers.platform_measurement_snapshot_verified);
        measured_boot_console.printMeasurementSummary(&boot);
        supportMeasuredBootShape(&boot);
        return self.recordMeasurementComparison(&boot);
    }

    /// Hashes every boot artifact once, recording the same digests in the boot
    /// record and in the expected manifest that the snapshot is checked against.
    fn measureProductionArtifacts(
        self: *const TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
        recorder: *measured_boot.Recorder,
        artifact_manifest: *measured_boot.ArtifactManifest,
    ) !void {
        const kernel_digest = try productionKernelMeasurementDigest();
        const base_manifest_digest = self.productionBaseImageManifestDigest(graph);
        const policy_digest = self.productionPolicyDigest(graph);
        try measured_boot.addMeasuredArtifact(recorder, artifact_manifest, .kernel, "bootloader+kernel-zigos-native", &kernel_digest);
        try measured_boot.addMeasuredArtifact(recorder, artifact_manifest, .base_image, "production-native-base", &base_manifest_digest);
        try measured_boot.addMeasuredArtifact(recorder, artifact_manifest, .policy, "production-policy-set", &policy_digest);

        for (critical_service_classes) |class| {
            const service = self.supervisor.findByClass(class) orelse return error.MissingBootstrapLaunch;
            const image = self.criticalServiceImage(service) orelse return error.MissingUserspaceImage;
            try measured_boot.addMeasuredCriticalServiceImage(recorder, artifact_manifest, service, image);
        }
        try measured_boot.addMeasuredDriverSet(recorder, artifact_manifest, "production-driver-set", self.driver_directory);
    }

    fn verifyGeneratedProductionArtifactManifest(self: *const TrustBoot) bool {
        if (builtin.target.os.tag != .freestanding) return true;

        const root = @import("root");
        if (!@hasDecl(root, "production_artifact_manifest")) {
            return failGeneratedArtifactManifest("missing_generated_manifest");
        }
        var generated_manifest: measured_boot.BuildArtifactManifest = undefined;
        measured_boot.buildArtifactManifestFromGeneratedInto(&generated_manifest, root.production_artifact_manifest) catch {
            return failGeneratedArtifactManifest("generated_manifest_invalid");
        };
        if (!generated_manifest.hasRequiredShape()) {
            return failGeneratedArtifactManifest("generated_manifest_incomplete");
        }

        const bootloader_source_digest = bootloaderSourceDigest() catch {
            return failGeneratedArtifactManifest("bootloader_source_digest");
        };
        if (!measured_boot.buildArtifactDigestMatches(
            &generated_manifest,
            .bootloader_source,
            buildBootloaderSourceLabel(),
            &bootloader_source_digest,
        )) return failGeneratedArtifactManifest("bootloader_source_mismatch");

        const bootloader_measurement_digest = bootDescriptorDigest() catch {
            return failGeneratedArtifactManifest("bootloader_measurement_digest");
        };
        if (config.smokeFaultIs(.tampered_bootloader_measurement)) {
            var tampered_measurement_digest = bootloader_measurement_digest;
            tampered_measurement_digest[0] ^= 0x7B;
            if (measured_boot.buildArtifactDigestMatches(
                &generated_manifest,
                .boot_descriptor,
                build_bootloader_measurement_label,
                &tampered_measurement_digest,
            )) return failGeneratedArtifactManifest("tampered_measurement_accepted");
            common.printBootMarker(boot_markers.platform_bootloader_measurement_tamper_rejected);
            return false;
        }
        if (!measured_boot.buildArtifactDigestMatches(
            &generated_manifest,
            .boot_descriptor,
            build_bootloader_measurement_label,
            &bootloader_measurement_digest,
        )) return failGeneratedArtifactManifest("bootloader_measurement_mismatch");

        var userspace_artifact_count: usize = 0;
        for (generated_manifest.entries[0..generated_manifest.entry_count]) |entry| {
            if (entry.kind != .userspace_image) continue;
            const image = self.userspace_catalog.findByBundleId(entry.labelSlice()) orelse {
                return failGeneratedArtifactManifest("userspace_image_missing");
            };
            if (!image.bundle_signed) return failGeneratedArtifactManifest("userspace_image_unsigned");
            if (!std.mem.eql(u8, &image.file_sha256, &entry.digest)) {
                return failGeneratedArtifactManifest("userspace_image_digest_mismatch");
            }
            userspace_artifact_count += 1;
        }
        if (userspace_artifact_count != self.userspace_catalog.imageCount()) {
            return failGeneratedArtifactManifest("userspace_image_count_mismatch");
        }

        common.printBootMarker(boot_markers.platform_boot_descriptor_verified);
        common.printBootMarker(boot_markers.platform_build_artifact_manifest_verified);
        return true;
    }

    pub fn productionBaseImageManifestDigest(
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

    pub fn productionPolicyDigest(
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
        for (&self.service_directory.registry.bindings, 0..) |*binding, interface_index| {
            if (binding.service_id == 0) continue;
            const contract = &component_abi_schema.contracts[interface_index];
            crypto_hash.updateInt(&hasher, "registry-service-id", binding.service_id);
            crypto_hash.updateInt(&hasher, "registry-owner-task-id", self.registeredServiceOwnerTaskId(binding));
            crypto_hash.updateInt(&hasher, "registry-endpoint-id", binding.endpoint_id);
            crypto_hash.updateInt(&hasher, "registry-endpoint-capability-id", binding.endpoint_capability_id);
            crypto_hash.updateInt(&hasher, "registry-interface-id", @backingInt(contract.interface_id));
            crypto_hash.updateBytes(&hasher, "registry-interface-name", contract.interface.name);
            crypto_hash.updateInt(&hasher, "registry-version-major", contract.interface.version_major);
            crypto_hash.updateInt(&hasher, "registry-version-minor", contract.interface.version_minor);
            crypto_hash.updateInt(&hasher, "registry-flags", native_service_registry.REQUIRED_BINDING_FLAGS);
            crypto_hash.updateInt(&hasher, "registry-contract-hash", contract.contract_hash);
        }
        return crypto_hash.finalize(&hasher);
    }

    fn registeredServiceOwnerTaskId(
        self: *const TrustBoot,
        binding: *const native_service_registry.Binding,
    ) u64 {
        const endpoint_capability = self.capability_table.query(binding.endpoint_capability_id) orelse return 0;
        if (endpoint_capability.target.kind != .endpoint or endpoint_capability.target.id != binding.endpoint_id) return 0;
        return endpoint_capability.scope.task_id orelse 0;
    }

    fn criticalServiceImage(
        self: *const TrustBoot,
        service_record: *const supervisor_mod.ServiceRecord,
    ) ?*const userspace_loader.ImageRecord {
        const bundle_id = service_catalog.bundleIdForServiceClass(service_record.class) orelse return null;
        return self.userspace_catalog.findByBundleId(bundle_id);
    }

    fn recordMeasurementComparison(self: *TrustBoot, boot: *const measured_boot.BootRecord) bool {
        const measurement_signer = signing.SignerIdentity{
            .label = "zigos-measured-boot-state",
            .seed = signing.seedFromByte(0xA6),
        };
        const storage = &self.native_store.storage_service_instance;
        var journal = measured_boot.MeasurementJournal.init(
            storage,
            session_bootstrap.principals().package_service,
            measurement_signer,
        ) catch return false;
        var comparison = journal.record(boot.*, 130) catch return false;
        if (comptime includesVerificationEvidence()) {
            recordDirectMeasuredBootSummary(storage.service_id, &comparison);
        }
        self.native_store.checkpoint();
        if (comparison.previous == null) {
            common.printBootMarker(boot_markers.platform_measured_boot_first);
            return true;
        }
        if (comparison.same_root_digest) {
            common.printBootMarker(boot_markers.platform_measured_boot_same_root);
        }
        if (comparison.same_record_shape) {
            common.printBootMarker(boot_markers.platform_measured_boot_same_shape);
        }
        return true;
    }
};

fn productionKernelMeasurementDigest() !crypto_hash.Digest {
    var hasher = crypto_hash.init();
    const bootloader_digest = try bootDescriptorDigest();
    const kernel_digest = try kernelImageDigest();
    crypto_hash.updateBytes(&hasher, "bootloader-measurement-digest", &bootloader_digest);
    crypto_hash.updateBytes(&hasher, "kernel-image-digest", &kernel_digest);
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (!@hasDecl(root, "bootImageDigest")) return error.MissingBootImage;
        const image_digest = try root.bootImageDigest();
        crypto_hash.updateBytes(&hasher, "efi-embedded-payload", &image_digest);
    }
    return crypto_hash.finalize(&hasher);
}

fn productionRootProvenance() measured_boot.RootProvenance {
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (@hasDecl(root, "bootImageAuthenticated") and root.bootImageAuthenticated()) return .firmware_authenticated;
        return .unverified_boot;
    }
    return .emulator_provided;
}

fn bootDescriptorDigest() !crypto_hash.Digest {
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (@hasDecl(root, "bootDescriptorDigest")) {
            return root.bootDescriptorDigest();
        }
        return error.MissingBootloaderMeasurement;
    }
    return emulatorBootDescriptorDigest();
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

fn emulatorBootDescriptorDigest() crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "measurement-source", "host-emulator-bootloader-measurement");
    crypto_hash.updateBytes(&hasher, "bootloader", "efi");
    crypto_hash.updateBytes(&hasher, "entry", buildBootloaderSourceLabel());
    return crypto_hash.finalize(&hasher);
}

fn failGeneratedArtifactManifest(reason: []const u8) bool {
    common.printBootMarker("ZIGOS:PLATFORM:ARTIFACT_MANIFEST:FAIL");
    console.print(reason);
    console.print("\n");
    return false;
}

fn buildBootloaderSourceLabel() []const u8 {
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (@hasDecl(root, "bootloaderSourcePath")) return root.bootloaderSourcePath();
    }
    return "src/boot/efi_stub.zig";
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
    const descriptor = service.descriptor();
    crypto_hash.updateInt(hasher, "service-id", service.id);
    crypto_hash.updateEnum(hasher, "service-class", service.class);
    crypto_hash.updateEnum(hasher, "service-boundary", descriptor.boundary);
    hashPrincipal(hasher, "service-owner", service.owner);
    crypto_hash.updateBool(hasher, "service-restartable", descriptor.restartable);
    crypto_hash.updateEnum(hasher, "service-network-privilege", descriptor.isolation.network);
    crypto_hash.updateEnum(hasher, "service-storage-privilege", descriptor.isolation.storage);
    crypto_hash.updateEnum(hasher, "service-ui-privilege", descriptor.isolation.ui);
    if (descriptor.isolation.driver_class) |driver_class| {
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

fn includesVerificationEvidence() bool {
    if (builtin.target.os.tag != .freestanding) return false;
    return @import("../../kernel/config.zig").includesVerificationEvidence();
}

const DirectArtifactTamperFixture = struct {
    kind: measured_boot.MeasurementKind,
    marker: []const u8,
};

inline fn directArtifactTamperFixture() ?DirectArtifactTamperFixture {
    if (config.smokeFaultIs(.tampered_kernel)) return .{ .kind = .kernel, .marker = boot_markers.platform_artifact_kernel_tamper_rejected };
    if (config.smokeFaultIs(.tampered_userspace_image)) return .{ .kind = .critical_service, .marker = boot_markers.platform_artifact_userspace_image_tamper_rejected };
    if (config.smokeFaultIs(.tampered_policy)) return .{ .kind = .policy, .marker = boot_markers.platform_artifact_policy_tamper_rejected };
    if (config.smokeFaultIs(.tampered_driver_set)) return .{ .kind = .driver_set, .marker = boot_markers.platform_artifact_driver_set_tamper_rejected };
    return null;
}

fn rejectDirectArtifactTamper(
    handoff: *const measured_boot.MeasurementSnapshot,
    artifact_manifest: *const measured_boot.ArtifactManifest,
    kind: measured_boot.MeasurementKind,
    marker: []const u8,
) void {
    var tampered_handoff = handoff.*;
    if (!tamperFirstHandoffRecord(&tampered_handoff, kind)) return;

    _ = measured_boot.verifyMeasurementSnapshot(
        &tampered_handoff,
        artifact_manifest,
        productionRootProvenance(),
    ) catch |err| switch (err) {
        error.ManifestMismatch,
        error.UntrustedRootProvenance,
        => common.printBootMarker(marker),
        else => {},
    };
}

fn tamperFirstHandoffRecord(
    handoff: *measured_boot.MeasurementSnapshot,
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
            common.printBootMarker(boot_markers.platform_boot_image_authenticated);
            common.printBootMarker(boot_markers.platform_measured_boot_verified_root);
        } else if (boot.root_provenance == .unverified_boot) {
            common.printBootMarker(boot_markers.platform_boot_image_unverified);
        }
    }
}

/// Verification kernels leave storage checkpointing disabled, so their measured
/// boot journal does not survive a cold reboot. They carry the boot summary in
/// a raw sector instead and fall back to it when the journal has no previous
/// record. Production kernels rely on the checkpointed journal alone.
fn recordDirectMeasuredBootSummary(storage_service_id: u64, comparison: *measured_boot.BootComparison) void {
    const current = comparison.current;
    if (comparison.previous == null) {
        if (loadDirectMeasuredBootSummary(storage_service_id)) |previous| {
            comparison.previous = previous;
            comparison.same_root_digest = std.mem.eql(u8, &previous.root_digest, &current.root_digest);
            comparison.same_generation = previous.generation == current.generation;
            comparison.same_record_shape = previous.record_count == current.record_count and
                std.mem.eql(u16, &previous.kind_counts, &current.kind_counts);
        }
    }
    _ = storeDirectMeasuredBootSummary(storage_service_id, current);
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
    var sector = @as([direct_measured_boot_sector_size]u8, @splat(0));
    if (!readDirectMeasuredBootSector(storage_service_id, &sector)) return null;
    if (!std.mem.eql(u8, sector[direct_measured_boot_magic_offset..][0..direct_measured_boot_magic.len], direct_measured_boot_magic)) return null;
    if (std.mem.readInt(u16, sector[direct_measured_boot_version_offset..][0..@sizeOf(u16)], .little) != direct_measured_boot_version) return null;

    var summary = measured_boot.BootSummary{
        .generation = std.mem.readInt(u64, sector[direct_measured_boot_generation_offset..][0..@sizeOf(u64)], .little),
        .record_count = std.mem.readInt(u16, sector[direct_measured_boot_record_count_offset..][0..@sizeOf(u16)], .little),
        .kind_counts = @as([measured_boot.MEASUREMENT_KIND_COUNT]u16, @splat(0)),
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
    var sector = @as([direct_measured_boot_sector_size]u8, @splat(0));
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

    const root_volume = storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    return root_volume.attached_backend_read(direct_measured_boot_lba, buffer.ptr, buffer.len);
}

fn writeDirectMeasuredBootSector(storage_service_id: u64, buffer: *const [direct_measured_boot_sector_size]u8) bool {
    if (bootstrap_driver_port.activeStorageWrite(storage_service_id, direct_measured_boot_lba, buffer[0..])) {
        return bootstrap_driver_port.activeStorageFlush(storage_service_id);
    }

    const root_volume = storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    return volume_backend.writeAttachedDurableRange(root_volume, direct_measured_boot_lba, buffer[0..]);
}
