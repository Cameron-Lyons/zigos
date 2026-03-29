const builtin = @import("builtin");
const abi = @import("../core/abi.zig");
const contract = @import("../session/contract.zig");
const manifest = @import("../policy/manifest.zig");
const registry = @import("userspace_registry.zig");
const std = @import("std");
const task_runtime = @import("task_runtime.zig");
const userspace_loader = @import("userspace_loader.zig");

pub const Error = userspace_loader.Error || error{
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
    return .{
        .bundle_id = spec.bundle_id,
        .display_name = spec.display_name,
        .publisher = spec.publisher,
        .signature = signatureFor(spec),
    };
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

pub fn registerAll(catalog: *userspace_loader.Catalog) Error!void {
    if (builtin.target.os.tag == .freestanding) {
        const archive = @import("userspace_archive");
        inline for (archive.artifacts) |artifact| {
            _ = try catalog.registerEmbeddedArtifact(.{
                .bundle = .{
                    .bundle_id = artifact.bundle_id,
                    .display_name = artifact.display_name,
                    .publisher = artifact.publisher,
                    .signature = signatureForPublisher(artifact.publisher, artifact.signed),
                },
                .component_class = componentClassFromByte(artifact.component_class),
                .initial_component = .{
                    .label = artifact.label,
                    .entry = artifact.entry,
                },
                .elf_bytes = artifact.data,
            });
        }
        return;
    }

    for (registry.boot_image_specs) |spec| {
        _ = try catalog.register(.{
            .bundle = .{
                .bundle_id = spec.bundle_id,
                .display_name = spec.display_name,
                .publisher = spec.publisher,
                .signature = signatureFor(&spec),
            },
            .component_class = switch (spec.component_class) {
                .session_manager => .session_manager,
                .app_component => .app_component,
                .service_component => .service_component,
            },
            .initial_component = .{
                .label = spec.label,
                .entry = spec.entry,
            },
        });
    }
}

pub fn bundleIdForServiceClass(class: contract.ServiceClass) Error![]const u8 {
    return switch (class) {
        .policy_mediation => "zigos.system.policy-mediation",
        .network_stack => "zigos.system.network-stack",
        .storage_object => "zigos.system.storage-object",
        .package_install_update => "zigos.system.package-service",
        .compositor_ui_session => "zigos.system.compositor",
        .indexing_search => "zigos.system.indexing-search",
        .sync_replication => "zigos.system.sync-service",
        .media_print_helpers => "zigos.system.media-print",
        else => error.UnsupportedServiceClass,
    };
}

fn signatureFor(spec: *const registry.ImageSpec) manifest.Signature {
    return signatureForPublisher(spec.publisher, spec.signed);
}

fn signatureForPublisher(publisher: []const u8, signed: bool) manifest.Signature {
    if (!signed) return .{};
    return .{
        .format = "ed25519",
        .signer = if (std.mem.eql(u8, publisher, "zigos.system"))
            "zigos-system-key"
        else
            "zigos-dev-key",
    };
}

fn componentClassFromByte(value: u8) task_runtime.ComponentClass {
    return switch (value) {
        @intFromEnum(registry.ComponentClass.session_manager) => .session_manager,
        @intFromEnum(registry.ComponentClass.app_component) => .app_component,
        else => .service_component,
    };
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
}
