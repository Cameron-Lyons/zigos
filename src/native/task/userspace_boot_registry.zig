const builtin = @import("builtin");
const contract = @import("../session/contract.zig");
const manifest = @import("../policy/manifest.zig");
const registry = @import("userspace_registry.zig");
const std = @import("std");
const task_runtime = @import("task_runtime.zig");
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
    UnsupportedServiceClass,
    UnknownBundleId,
};

pub fn specCount() usize {
    return registry.boot_image_specs.len;
}

pub fn find(bundle_id: []const u8) ?*const registry.ImageSpec {
    return registry.find(bundle_id);
}

pub fn manifestFor(bundle_id: []const u8) Error!manifest.BundleManifest {
    const spec = find(bundle_id) orelse return error.UnknownBundleId;
    return bundleForSpec(spec);
}

pub fn initialComponentFor(bundle_id: []const u8) Error!task_runtime.ExecutionComponentSpec {
    const spec = find(bundle_id) orelse return error.UnknownBundleId;
    return .{
        .label = spec.label,
        .entry = spec.entry,
    };
}

pub fn componentClassFor(bundle_id: []const u8) Error!task_runtime.ComponentClass {
    const spec = find(bundle_id) orelse return error.UnknownBundleId;
    return switch (spec.component_class) {
        .session_manager => .session_manager,
        .app_component => .app_component,
        .service_component => .service_component,
    };
}

pub fn signerFor(bundle_id: []const u8) Error![]const u8 {
    const spec = find(bundle_id) orelse return error.UnknownBundleId;
    return (try userspace_manifest_signing.identityForPublisher(spec.publisher)).label;
}

pub fn registerAll(catalog: *userspace_loader.Catalog) Error!void {
    if (builtin.target.os.tag == .freestanding) {
        const archive = @import("userspace_archive");
        inline for (archive.artifacts) |artifact| {
            const spec = find(artifact.bundle_id) orelse return error.UnknownBundleId;
            const bundle = try bundleForSpec(spec);
            const embedded_info = embeddedElfInfoFromArtifact(artifact);
            _ = catalog.registerEmbeddedArtifactWithInfo(.{
                .bundle = bundle,
                .component_class = componentClassForSpec(spec),
                .initial_component = initialComponentForSpec(spec),
                .role_tag = spec.role_tag,
                .heartbeat_increment = spec.heartbeat_increment,
                .contract_flags = spec.contract_flags,
                .elf_bytes = artifact.data,
            }, embedded_info) catch |err| {
                console.print("ZIGOS:USERSPACE:ARTIFACT:FAIL ");
                console.print(artifact.bundle_id);
                console.print("\n");
                return err;
            };
        }
        return;
    }

    for (registry.boot_image_specs) |spec| {
        const bundle = try bundleForSpec(&spec);
        _ = try catalog.register(.{
            .bundle = bundle,
            .component_class = componentClassForSpec(&spec),
            .initial_component = initialComponentForSpec(&spec),
            .role_tag = spec.role_tag,
            .heartbeat_increment = spec.heartbeat_increment,
            .contract_flags = spec.contract_flags,
        });
    }
}

pub fn bundleIdForServiceClass(class: contract.ServiceClass) Error![]const u8 {
    const spec = registry.findByServiceClass(class) orelse return error.UnsupportedServiceClass;
    return spec.bundle_id;
}

fn signatureFor(bundle: manifest.BundleManifest, signed: bool) SigningError!manifest.Signature {
    if (!signed) return .{};
    return userspace_manifest_signing.signBundle(bundle);
}

fn bundleForSpec(spec: *const registry.ImageSpec) Error!manifest.BundleManifest {
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

fn initialComponentForSpec(spec: *const registry.ImageSpec) task_runtime.ExecutionComponentSpec {
    return .{
        .label = spec.label,
        .entry = spec.entry,
    };
}

fn componentClassForSpec(spec: *const registry.ImageSpec) task_runtime.ComponentClass {
    return switch (spec.component_class) {
        .session_manager => .session_manager,
        .app_component => .app_component,
        .service_component => .service_component,
    };
}

fn embeddedElfInfoFromArtifact(artifact: anytype) userspace_loader.EmbeddedElfInfo {
    return .{
        .entry_point = artifact.entry_point,
        .loadable_segment_count = @intCast(artifact.segment_count),
        .byte_len = artifact.file_size_bytes,
        .bootstrap_mailbox_address = artifact.bootstrap_mailbox_address,
        .file_sha256 = artifact.file_sha256,
        .executable_image = executableImageFromArtifact(artifact),
    };
}

fn executableImageFromArtifact(artifact: anytype) task_runtime.ExecutableImageSpec {
    var executable_image = task_runtime.ExecutableImageSpec{
        .entry_point = artifact.entry_point,
        .stack_top = artifact.stack_top,
        .stack_size_bytes = artifact.stack_size_bytes,
        .file_size_bytes = artifact.file_size_bytes,
        .file_sha256 = artifact.file_sha256,
        .segment_count = artifact.segment_count,
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

    try std.testing.expect(specCount() >= 10);
    try std.testing.expect(find("zigos.system.session-manager") != null);
    try std.testing.expect(find("app.notes") != null);
    try std.testing.expectEqualStrings(
        "zigos.system.storage-object",
        try bundleIdForServiceClass(.storage_object),
    );
    try std.testing.expect(catalog.findByBundleId("zigos.system.session-manager") != null);
    try std.testing.expect(catalog.findByBundleId("app.capture") != null);
    try std.testing.expect(catalog.findByBundleId("zigos.system.session-manager").?.hasTypedContract());
    try std.testing.expect(catalog.findByBundleId("app.capture").?.hasTypedContract());
    try std.testing.expect(catalog.findByBundleId("zigos.system.session-manager").?.bundle_signed);
}
