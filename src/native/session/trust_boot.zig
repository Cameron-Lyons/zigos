const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const driver_service = @import("../drivers/driver_service.zig");
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
const userspace_loader = @import("../task/userspace_loader.zig");

const build_bootloader_measurement_label = "multiboot-v1:zigos_native";
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

const native_measured_boot_storage = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn zigosStorageBootstrapAtaRead(
            device: *const anyopaque,
            start_lba: u64,
            buffer_ptr: [*]u8,
            buffer_len: usize,
        ) callconv(.c) bool;

        extern fn zigosStorageBootstrapAtaWrite(
            device: *const anyopaque,
            start_lba: u64,
            buffer_ptr: [*]const u8,
            buffer_len: usize,
        ) callconv(.c) bool;
    }
else
    struct {};

pub const TrustBoot = struct {
    userspace_catalog: *userspace_loader.Catalog,
    capability_table: *capability.CapabilityTable,
    service_directory: *native_service_registry.Service,
    supervisor: *supervisor_mod.Supervisor,
    driver_directory: *driver_service.Directory,
    native_store: *native_store_mount.NativeStoreMount,

    pub fn init(
        runtime_context: *session_contexts.RuntimeContext,
        kernel_context: *session_contexts.KernelContext,
        graph_builder: *service_graph_builder_mod.Builder,
        native_store: *native_store_mount.NativeStoreMount,
    ) TrustBoot {
        return .{
            .userspace_catalog = &runtime_context.userspace_catalog,
            .capability_table = &kernel_context.capability_table,
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
        const manifest_signer = signing.SignerIdentity{
            .label = "zigos-artifact-manifest",
            .seed = [_]u8{0xB7} ** 32,
        };
        const artifact_manifest = self.buildProductionArtifactManifest(graph) catch return false;
        if (builtin.target.os.tag == .freestanding) {
            if (!self.verifyGeneratedProductionArtifactManifest(true)) return false;
            common.printBootMarker(boot_markers.platform_artifact_manifest_verified);
            return true;
        }
        const signed_manifest = measured_boot.signArtifactManifest(artifact_manifest, manifest_signer) catch return false;
        if (!measured_boot.verifySignedArtifactManifest(&signed_manifest)) return false;
        common.printBootMarker(boot_markers.platform_artifact_manifest_verified);
        return true;
    }

    pub fn proveProductionAbImageRollback(
        self: *TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
    ) bool {
        const state_signer = signing.SignerIdentity{
            .label = "zigos-base-state",
            .seed = [_]u8{0xA1} ** 32,
        };
        const image_signer = signing.SignerIdentity{
            .label = "zigos-base-image",
            .seed = [_]u8{0xA2} ** 32,
        };

        var base_manager = immutable_base.Manager.init(
            &self.native_store.storage_service_instance,
            graph.state.ids.package_service,
            state_signer,
        ) catch return false;
        _ = base_manager.stageImage(0, "stable-a", "zigos-native-base:stable-a", image_signer, 70) catch return false;
        const stable = base_manager.activate(0, .{}, 71) catch return false;
        if (stable.rolled_back or stable.active_slot == null or stable.active_slot.? != 0) return false;

        _ = base_manager.stageImage(1, "stable-b", "zigos-native-base:stable-b", image_signer, 72) catch return false;
        const rolled_back = base_manager.activate(1, .{ .network_ok = false }, 73) catch return false;
        if (!rolled_back.rolled_back) return false;
        if (rolled_back.active_slot == null or rolled_back.active_slot.? != 0) return false;
        if (!base_manager.verifyActiveImage()) return false;

        common.printBootMarker(boot_markers.platform_immutable_base_active);
        common.printBootMarker(boot_markers.platform_activation_rollback_ok);
        common.printBootMarker(boot_markers.platform_ab_image_rollback_ok);
        return true;
    }

    pub fn recordProductionMeasuredBoot(
        self: *TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
    ) bool {
        const manifest_signer = signing.SignerIdentity{
            .label = "zigos-artifact-manifest",
            .seed = [_]u8{0xB7} ** 32,
        };
        const artifact_manifest = self.buildProductionArtifactManifest(graph) catch return false;
        if (builtin.target.os.tag == .freestanding) {
            if (!self.verifyGeneratedProductionArtifactManifest(false)) return false;
        } else {
            const signed_manifest = measured_boot.signArtifactManifest(artifact_manifest, manifest_signer) catch return false;
            if (!measured_boot.verifySignedArtifactManifest(&signed_manifest)) return false;
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

        const boot = measured.finalize();
        if (!measured_boot.bootRecordMatchesManifest(&boot, &artifact_manifest)) return false;
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

        const bootloader_digest = bootloaderProvidedMeasurementDigest() catch return false;
        const bootloader_entry = generated_manifest.find(
            .bootloader_measurement,
            build_bootloader_measurement_label,
        ) orelse return false;
        if (!std.mem.eql(u8, &bootloader_entry.digest, &bootloader_digest)) return false;

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
    ) [32]u8 {
        var hasher = crypto_hash.init();
        hashPrincipal(&hasher, "policy-authority", graph.state.ids.policy_authority);
        hashPrincipal(&hasher, "session-service", graph.state.ids.session_service);
        crypto_hash.updateInt(&hasher, "session-task-id", graph.state.session_task.id);
        crypto_hash.updateInt(&hasher, "review-service-task-id", graph.state.review_service_task.id);

        for (self.supervisor.service_arena.slots) |slot| {
            if (!slot.in_use) continue;
            hashServiceRecord(&hasher, &slot.service);
        }
        for (graph.service_bindings.bindings) |binding| {
            crypto_hash.updateInt(&hasher, "binding-task-id", binding.task_id);
            crypto_hash.updateInt(&hasher, "binding-endpoint-id", binding.endpoint_id);
        }
        for (self.userspace_catalog.images) |slot| {
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

    fn productionPolicyDigest(
        self: *const TrustBoot,
        graph: *const service_graph_builder_mod.ServiceGraph,
    ) [32]u8 {
        var hasher = crypto_hash.init();
        hashPrincipal(&hasher, "session-capability-holder", graph.state.session_capability.holder);
        hashCapability(&hasher, "session-capability", &graph.state.session_capability);
        hashCapability(&hasher, "policy-capability", &graph.state.policy_capability);

        for (self.capability_table.slots) |slot| {
            if (!slot.in_use) continue;
            hashCapability(&hasher, "capability", &slot.capability);
        }
        for (self.service_directory.registry.bindings.slots) |slot| {
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
            .seed = [_]u8{0xA6} ** 32,
        };
        const direct_previous = loadDirectMeasuredBootSummary();
        var journal = measured_boot.MeasurementJournal.init(
            &self.native_store.storage_service_instance,
            session_bootstrap.principals().package_service,
            measurement_signer,
        ) catch unreachable;
        var comparison = journal.record(boot.*, 130) catch unreachable;
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
        _ = storeDirectMeasuredBootSummary(current_summary);
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
};

fn productionKernelMeasurementDigest() ![32]u8 {
    var hasher = crypto_hash.init();
    const bootloader_digest = try bootloaderProvidedMeasurementDigest();
    const kernel_digest = try kernelImageDigest();
    crypto_hash.updateBytes(&hasher, "bootloader-measurement-digest", &bootloader_digest);
    crypto_hash.updateBytes(&hasher, "kernel-image-digest", &kernel_digest);
    return crypto_hash.finalize(&hasher);
}

fn bootloaderProvidedMeasurementDigest() ![32]u8 {
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (@hasDecl(root, "bootloaderMeasurementDigest")) {
            return root.bootloaderMeasurementDigest();
        }
        return error.MissingBootloaderMeasurement;
    }
    return syntheticBootloaderMeasurementDigest();
}

fn kernelImageDigest() ![32]u8 {
    if (builtin.target.os.tag == .freestanding) {
        const root = @import("root");
        if (@hasDecl(root, "kernelImageDigest")) {
            return root.kernelImageDigest();
        }
        return error.MissingKernelMeasurement;
    }
    return syntheticKernelImageDigest();
}

fn syntheticBootloaderMeasurementDigest() [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "measurement-source", "host-synthetic-bootloader-measurement");
    crypto_hash.updateBytes(&hasher, "bootloader", "multiboot-v1");
    crypto_hash.updateBytes(&hasher, "entry", "src/boot/boot64.S");
    return crypto_hash.finalize(&hasher);
}

fn syntheticKernelImageDigest() [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "measurement-source", "host-synthetic-kernel-image");
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
    crypto_hash.updateInt(hasher, "capability-issued-at", cap.lease.issued_at_ticks);
    crypto_hash.updateInt(hasher, "capability-expires-at", cap.lease.expires_at_ticks);
    crypto_hash.updateBool(hasher, "capability-renewable", cap.lease.renewable);
    crypto_hash.updateInt(hasher, "capability-revocation-generation", cap.revocation_generation);
    crypto_hash.updateInt(hasher, "capability-policy-generation", cap.audit.policy_generation);
    crypto_hash.updateInt(hasher, "capability-source-task-id", cap.audit.source_task_id);
    crypto_hash.updateInt(hasher, "capability-broker-service-id", cap.audit.broker_service_id);
}

fn supportMeasuredBootShape(boot: *const measured_boot.BootRecord) void {
    if (boot.countKind(.kernel) == 1 and
        boot.countKind(.base_image) == 1 and
        boot.countKind(.critical_service) == critical_service_classes.len and
        boot.countKind(.policy) == 1 and
        boot.countKind(.driver_set) == 1 and
        !std.mem.allEqual(u8, &boot.root_digest, 0))
    {
        common.printBootMarker(boot_markers.platform_measured_boot_recorded);
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

fn loadDirectMeasuredBootSummary() ?measured_boot.BootSummary {
    if (builtin.target.os.tag != .freestanding) return null;
    var sector = [_]u8{0} ** direct_measured_boot_sector_size;
    if (!readDirectMeasuredBootSector(&sector)) return null;
    if (!std.mem.eql(u8, sector[direct_measured_boot_magic_offset..][0..direct_measured_boot_magic.len], direct_measured_boot_magic)) return null;
    if (std.mem.readInt(u16, sector[direct_measured_boot_version_offset..][0..@sizeOf(u16)], .little) != direct_measured_boot_version) return null;

    var summary = measured_boot.BootSummary{
        .generation = std.mem.readInt(u64, sector[direct_measured_boot_generation_offset..][0..@sizeOf(u64)], .little),
        .record_count = std.mem.readInt(u16, sector[direct_measured_boot_record_count_offset..][0..@sizeOf(u16)], .little),
        .kind_counts = [_]u16{0} ** measured_boot.MEASUREMENT_KIND_COUNT,
        .root_digest = [_]u8{0} ** 32,
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

fn storeDirectMeasuredBootSummary(summary: measured_boot.BootSummary) bool {
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
    return writeDirectMeasuredBootSector(&sector);
}

fn readDirectMeasuredBootSector(buffer: *[direct_measured_boot_sector_size]u8) bool {
    const root = @import("root");
    if (!@hasDecl(root, "storage_volume")) return false;
    const root_volume = root.storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    if (root_volume.attached_ata_device) |device| {
        return native_measured_boot_storage.zigosStorageBootstrapAtaRead(
            device,
            direct_measured_boot_lba,
            buffer.ptr,
            buffer.len,
        );
    }
    return root_volume.attached_backend_read(direct_measured_boot_lba, buffer.ptr, buffer.len);
}

fn writeDirectMeasuredBootSector(buffer: *const [direct_measured_boot_sector_size]u8) bool {
    const root = @import("root");
    if (!@hasDecl(root, "storage_volume")) return false;
    const root_volume = root.storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    if (root_volume.attached_ata_device) |device| {
        return native_measured_boot_storage.zigosStorageBootstrapAtaWrite(
            device,
            direct_measured_boot_lba,
            buffer.ptr,
            buffer.len,
        );
    }
    return root_volume.attached_backend_write(direct_measured_boot_lba, buffer.ptr, buffer.len);
}
