const builtin = @import("builtin");
const contract = @import("../session/contract.zig");
const embedded_file = @import("embedded_file.zig");
const manifest = @import("../policy/manifest.zig");
const service_catalog = @import("../session/service_catalog.zig");
const std = @import("std");
const task_runtime = @import("task_runtime.zig");
const archive_index = @import("userspace_archive_index.zig");
const role_registry = if (archive_index.includes_verification_images)
    @import("userspace_verification_registry.zig")
else
    @import("userspace_registry.zig");
const userspace_loader = @import("userspace_loader.zig");
const userspace_manifest_signing = @import("userspace_manifest_signing.zig");
const console = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

const SignBundleReturn = @typeInfo(@TypeOf(userspace_manifest_signing.signBundle)).@"fn".return_type.?;
const SigningError = @typeInfo(SignBundleReturn).error_union.error_set;

pub const Error = userspace_loader.Error || SigningError || error{
    GeneratedArtifactSegmentCountInvalid,
    GeneratedArtifactSignatureMismatch,
    UnsupportedServiceClass,
    UnknownBundleId,
};

const active_boot_image_specs: []const role_registry.ImageSpec = &role_registry.role_boot_image_specs;

comptime {
    if (active_boot_image_specs.len != archive_index.artifacts.len) {
        @compileError("generated userspace archive does not match its role-specific boot catalog");
    }
}

pub fn specCount() usize {
    return active_boot_image_specs.len;
}

pub fn find(bundle_id: []const u8) ?*const role_registry.ImageSpec {
    return role_registry.findForRole(bundle_id);
}

pub fn specAt(index: usize) ?*const role_registry.ImageSpec {
    if (index >= active_boot_image_specs.len) return null;
    return &active_boot_image_specs[index];
}

pub fn manifestFor(bundle_id: []const u8) Error!manifest.BundleManifest {
    const spec = find(bundle_id) orelse return error.UnknownBundleId;
    return bundleForSpec(spec);
}

pub fn signerFor(bundle_id: []const u8) Error![]const u8 {
    const spec = find(bundle_id) orelse return error.UnknownBundleId;
    return (try userspace_manifest_signing.identityForPublisher(spec.publisher)).label;
}

pub fn registerAll(catalog: *userspace_loader.Catalog) Error!void {
    for (active_boot_image_specs, 0..) |spec, artifact_index| {
        const artifact = archive_index.artifacts[artifact_index];
        try validateGeneratedArtifactMatchesSpec(&spec, artifact);
        const bundle = try bundleForSpec(&spec);
        const executable_image = try executableImageFromArtifact(artifact);
        _ = catalog.registerBuildValidatedArtifact(.{
            .bundle = bundle,
            .component_class = componentClassForSpec(&spec),
            .initial_component = initialComponentForSpec(&spec),
            .role_tag = spec.role_tag,
            .heartbeat_increment = spec.heartbeat_increment,
            .contract_flags = spec.contract_flags,
            .elf_file = embedded_file.File.fromChunkedArtifact(artifact),
        }, executable_image) catch |err| {
            console.print("ZIGOS:USERSPACE:ARTIFACT:FAIL ");
            console.print(spec.bundle_id);
            console.print("\n");
            return err;
        };
    }
}

pub fn validateGeneratedArtifactMatchesSpec(spec: *const role_registry.ImageSpec, artifact: anytype) Error!void {
    if (artifact.signed != spec.signed) return error.GeneratedArtifactSignatureMismatch;
    if (artifact.segment_count > task_runtime.MAX_EXECUTABLE_SEGMENTS) {
        return error.GeneratedArtifactSegmentCountInvalid;
    }
}

pub fn bundleIdForServiceClass(class: contract.ServiceClass) Error![]const u8 {
    return service_catalog.bundleIdForServiceClass(class) orelse error.UnsupportedServiceClass;
}

fn signatureFor(bundle: manifest.BundleManifest, signed: bool) SigningError!manifest.Signature {
    if (!signed) return .{};
    return userspace_manifest_signing.signBundle(bundle);
}

fn bundleForSpec(spec: *const role_registry.ImageSpec) Error!manifest.BundleManifest {
    var bundle = manifest.BundleManifest{
        .bundle_id = spec.bundle_id,
        .display_name = spec.display_name,
        .publisher = spec.publisher,
        .provided_interfaces = spec.provided_interfaces,
        .consumed_interfaces = spec.consumed_interfaces,
        .components = spec.components,
        .assets = spec.assets,
        .update_channel = spec.update_channel,
    };
    bundle.signature = try signatureFor(bundle, spec.signed);
    return bundle;
}

fn initialComponentForSpec(spec: *const role_registry.ImageSpec) task_runtime.ExecutionComponentSpec {
    return .{
        .label = spec.label,
        .entry = spec.entry,
    };
}

fn componentClassForSpec(spec: *const role_registry.ImageSpec) task_runtime.ComponentClass {
    return switch (spec.component_class) {
        .session_manager => .session_manager,
        .app_component => .app_component,
        .service_component => .service_component,
    };
}

fn executableImageFromArtifact(artifact: anytype) Error!task_runtime.ExecutableImageSpec {
    if (artifact.segment_count > task_runtime.MAX_EXECUTABLE_SEGMENTS) {
        return error.GeneratedArtifactSegmentCountInvalid;
    }
    var executable_image = task_runtime.ExecutableImageSpec{
        .entry_point = artifact.entry_point,
        .bootstrap_mailbox_address = artifact.bootstrap_mailbox_address,
        .stack_top = artifact.stack_top,
        .stack_size_bytes = artifact.stack_size_bytes,
        .file_size_bytes = artifact.file_size_bytes,
        .file_sha256 = artifact.file_sha256,
        .segment_count = @intCast(artifact.segment_count),
    };

    var index: usize = 0;
    while (index < artifact.segment_count) : (index += 1) {
        const segment = artifact.segments[index];
        executable_image.segments[index] = .{
            .virtual_address = segment.virtual_address,
            .file_offset = segment.file_offset,
            .file_size = segment.file_size,
            .memory_size = segment.memory_size,
            .alignment = segment.alignment,
            .access = .{
                .read = segment.access.read,
                .write = segment.access.write,
                .execute = segment.access.execute,
            },
        };
    }

    return executable_image;
}

test "boot registry definitions are unique and preload a userspace catalog" {
    var catalog = userspace_loader.Catalog.init();
    try registerAll(&catalog);

    try std.testing.expectEqual(archive_index.artifacts.len, specCount());
    try std.testing.expectEqual(specCount(), catalog.imageCount());
    try std.testing.expect(find("zigos.system.session-manager") != null);
    try std.testing.expect(find("app.notes") != null);
    try std.testing.expectEqualStrings(
        "zigos.system.storage-object",
        try bundleIdForServiceClass(.storage_object),
    );
    try std.testing.expect(catalog.findByBundleId("zigos.system.session-manager") != null);
    try std.testing.expect(catalog.findByBundleId("app.capture") != null);
    try std.testing.expect(catalog.findByBundleId("zigos.system.session-manager").?.embedsElf());
    try std.testing.expect(catalog.findByBundleId("app.capture").?.embedsElf());
    try std.testing.expect(catalog.findByBundleId("zigos.system.session-manager").?.hasTypedContract());
    try std.testing.expect(catalog.findByBundleId("app.capture").?.hasTypedContract());
    try std.testing.expect(catalog.findByBundleId("zigos.system.session-manager").?.bundle_signed);
    if (archive_index.includes_verification_images) {
        try std.testing.expect(find("zigos.proof.mmu-isolation") != null);
    } else {
        try std.testing.expect(find("zigos.proof.mmu-isolation") == null);
    }
}

test "boot registry rejects generated archive records that diverge from registry specs" {
    try std.testing.expect(archive_index.artifacts.len > 0);
    const spec = specAt(0) orelse return error.UnknownBundleId;

    try validateGeneratedArtifactMatchesSpec(spec, archive_index.artifacts[0]);
    _ = try executableImageFromArtifact(archive_index.artifacts[0]);

    var unsigned = archive_index.artifacts[0];
    unsigned.signed = !spec.signed;
    try std.testing.expectError(
        error.GeneratedArtifactSignatureMismatch,
        validateGeneratedArtifactMatchesSpec(spec, unsigned),
    );

    var too_many_segments = archive_index.artifacts[0];
    too_many_segments.segment_count = task_runtime.MAX_EXECUTABLE_SEGMENTS + 1;
    try std.testing.expectError(
        error.GeneratedArtifactSegmentCountInvalid,
        validateGeneratedArtifactMatchesSpec(spec, too_many_segments),
    );
    try std.testing.expectError(
        error.GeneratedArtifactSegmentCountInvalid,
        executableImageFromArtifact(too_many_segments),
    );
}
