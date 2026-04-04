const std = @import("std");
const contract = @import("../session/contract.zig");
const manifest = @import("../policy/manifest.zig");

pub const FLAG_SYSTEM_BUNDLE: u32 = 1 << 0;
pub const FLAG_OWNS_UI_SURFACE: u32 = 1 << 1;
pub const FLAG_PERMISSION_REVIEW: u32 = 1 << 2;
pub const FLAG_BACKGROUND_ELIGIBLE: u32 = 1 << 3;
pub const FLAG_STORAGE_BOUNDARY: u32 = 1 << 4;
pub const FLAG_NETWORK_BOUNDARY: u32 = 1 << 5;
pub const FLAG_POLICY_BOUNDARY: u32 = 1 << 6;
pub const FLAG_DRIVER_BOUNDARY: u32 = 1 << 7;
pub const FLAG_COMPATIBILITY_BOUNDARY: u32 = 1 << 8;

pub const ComponentClass = enum(u8) {
    session_manager,
    app_component,
    service_component,
};

pub const ContractSpec = struct {
    bundle_id: []const u8,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32,
};

pub const ImageSpec = struct {
    bundle_id: []const u8,
    artifact_name: []const u8,
    source_path: []const u8 = "src/userspace/component_main.zig",
    display_name: []const u8,
    publisher: []const u8,
    label: []const u8,
    entry: []const u8,
    components: []const manifest.ExecutionComponentDecl,
    provided_interfaces: []const manifest.InterfaceDecl = &.{},
    consumed_interfaces: []const manifest.InterfaceDecl = &.{},
    assets: []const manifest.AssetDecl = &.{},
    update_channel: manifest.UpdateChannel = .stable,
    component_class: ComponentClass,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32 = 0,
    service_class: ?contract.ServiceClass = null,
    signed: bool = true,
};

pub const boot_image_specs = [_]ImageSpec{
    .{
        .bundle_id = "zigos.system.session-manager",
        .artifact_name = "userspace-session-manager.elf",
        .display_name = "Session Manager",
        .publisher = "zigos.system",
        .label = "session-manager",
        .entry = "zigos.session.manager",
        .components = &.{.{ .id = "session-manager", .entry = "zigos.session.manager" }},
        .component_class = .session_manager,
        .role_tag = 0xA101,
        .heartbeat_increment = 1,
        .contract_flags = FLAG_SYSTEM_BUNDLE,
        .service_class = .session_manager,
    },
    .{
        .bundle_id = "zigos.system.permission-review",
        .artifact_name = "userspace-permission-review.elf",
        .display_name = "Permission Review",
        .publisher = "zigos.system",
        .label = "permission-review",
        .entry = "zigos.permission.review",
        .components = &.{.{ .id = "permission-review", .entry = "zigos.permission.review" }},
        .component_class = .service_component,
        .role_tag = 0xA102,
        .heartbeat_increment = 2,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_OWNS_UI_SURFACE | FLAG_PERMISSION_REVIEW,
        .service_class = .permission_review_ui,
    },
    .{
        .bundle_id = "zigos.system.workspace-storage",
        .artifact_name = "userspace-workspace-storage.elf",
        .display_name = "Workspace Storage",
        .publisher = "zigos.system",
        .label = "workspace-storage",
        .entry = "zigos.bootstrap.workspace",
        .components = &.{.{ .id = "workspace-storage", .entry = "zigos.bootstrap.workspace" }},
        .component_class = .service_component,
        .role_tag = 0xA103,
        .heartbeat_increment = 3,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_STORAGE_BOUNDARY,
    },
    .{
        .bundle_id = "zigos.system.transport-probe",
        .artifact_name = "userspace-transport-probe.elf",
        .display_name = "Transport Probe",
        .publisher = "zigos.system",
        .label = "transport-probe",
        .entry = "app.transport.probe",
        .components = &.{.{ .id = "transport-probe", .entry = "app.transport.probe" }},
        .component_class = .app_component,
        .role_tag = 0xA104,
        .heartbeat_increment = 4,
        .contract_flags = FLAG_OWNS_UI_SURFACE,
    },
    .{
        .bundle_id = "zigos.system.termination-probe",
        .artifact_name = "userspace-termination-probe.elf",
        .display_name = "Termination Probe",
        .publisher = "zigos.system",
        .label = "termination-probe",
        .entry = "app.termination.probe",
        .components = &.{.{ .id = "termination-probe", .entry = "app.termination.probe" }},
        .component_class = .app_component,
        .role_tag = 0xA105,
        .heartbeat_increment = 5,
    },
    .{
        .bundle_id = "app.viewer",
        .artifact_name = "userspace-viewer.elf",
        .display_name = "Viewer",
        .publisher = "zigos.dev",
        .label = "viewer",
        .entry = "app.viewer",
        .components = &.{.{ .id = "viewer", .entry = "app.viewer" }},
        .provided_interfaces = &.{.{ .name = "zigos.viewer.document" }},
        .consumed_interfaces = &.{.{ .name = "zigos.object.workspace" }},
        .assets = &.{.{ .path = "assets/viewer/icon.svg", .content_type = "image/svg+xml" }},
        .component_class = .app_component,
        .role_tag = 0xA106,
        .heartbeat_increment = 6,
        .contract_flags = FLAG_OWNS_UI_SURFACE,
    },
    .{
        .bundle_id = "app.notes",
        .artifact_name = "userspace-notes.elf",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .label = "notes",
        .entry = "app.notes",
        .components = &.{.{ .id = "notes", .entry = "app.notes" }},
        .provided_interfaces = &.{.{ .name = "zigos.workspace.document" }},
        .consumed_interfaces = &.{.{ .name = "zigos.object.workspace" }},
        .assets = &.{.{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" }},
        .update_channel = .beta,
        .component_class = .app_component,
        .role_tag = 0xA107,
        .heartbeat_increment = 7,
        .contract_flags = FLAG_OWNS_UI_SURFACE,
    },
    .{
        .bundle_id = "app.sync",
        .artifact_name = "userspace-sync.elf",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .label = "sync",
        .entry = "app.sync",
        .components = &.{.{ .id = "sync", .entry = "app.sync" }},
        .provided_interfaces = &.{.{ .name = "zigos.sync.replication" }},
        .consumed_interfaces = &.{.{ .name = "zigos.object.workspace" }},
        .assets = &.{.{ .path = "assets/sync/icon.svg", .content_type = "image/svg+xml" }},
        .component_class = .app_component,
        .role_tag = 0xA108,
        .heartbeat_increment = 8,
        .contract_flags = FLAG_BACKGROUND_ELIGIBLE,
    },
    .{
        .bundle_id = "app.capture",
        .artifact_name = "userspace-capture.elf",
        .display_name = "Capture",
        .publisher = "zigos.dev",
        .label = "capture",
        .entry = "app.capture",
        .components = &.{.{ .id = "capture", .entry = "app.capture" }},
        .provided_interfaces = &.{.{ .name = "zigos.capture.session" }},
        .consumed_interfaces = &.{.{ .name = "zigos.media.print" }},
        .assets = &.{.{ .path = "assets/capture/icon.svg", .content_type = "image/svg+xml" }},
        .component_class = .app_component,
        .role_tag = 0xA109,
        .heartbeat_increment = 9,
        .contract_flags = FLAG_OWNS_UI_SURFACE,
    },
    .{
        .bundle_id = "zigos.system.policy-mediation",
        .artifact_name = "userspace-policy-mediation.elf",
        .display_name = "Policy Mediation",
        .publisher = "zigos.system",
        .label = "policy-mediation",
        .entry = "zigos.policy.mediation",
        .components = &.{.{ .id = "policy-mediation", .entry = "zigos.policy.mediation" }},
        .component_class = .service_component,
        .role_tag = 0xA10A,
        .heartbeat_increment = 10,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_POLICY_BOUNDARY,
        .service_class = .policy_mediation,
    },
    .{
        .bundle_id = "zigos.system.network-stack",
        .artifact_name = "userspace-network-stack.elf",
        .display_name = "Network Stack",
        .publisher = "zigos.system",
        .label = "network-service",
        .entry = "zigos.service.network.policy",
        .components = &.{.{ .id = "network-service", .entry = "zigos.service.network.policy" }},
        .component_class = .service_component,
        .role_tag = 0xA10B,
        .heartbeat_increment = 11,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_NETWORK_BOUNDARY,
        .service_class = .network_stack,
    },
    .{
        .bundle_id = "zigos.system.storage-object",
        .artifact_name = "userspace-storage-object.elf",
        .display_name = "Storage Object Service",
        .publisher = "zigos.system",
        .label = "workspace-storage",
        .entry = "zigos.object.workspace",
        .components = &.{.{ .id = "workspace-storage", .entry = "zigos.object.workspace" }},
        .component_class = .service_component,
        .role_tag = 0xA10C,
        .heartbeat_increment = 12,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_STORAGE_BOUNDARY,
        .service_class = .storage_object,
    },
    .{
        .bundle_id = "zigos.system.storage-driver",
        .artifact_name = "userspace-storage-driver.elf",
        .display_name = "Storage Driver",
        .publisher = "zigos.system",
        .label = "storage-driver",
        .entry = "zigos.driver.storage",
        .components = &.{.{ .id = "storage-driver", .entry = "zigos.driver.storage" }},
        .component_class = .service_component,
        .role_tag = 0xA10D,
        .heartbeat_increment = 13,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_DRIVER_BOUNDARY | FLAG_STORAGE_BOUNDARY,
    },
    .{
        .bundle_id = "zigos.system.package-service",
        .artifact_name = "userspace-package-service.elf",
        .display_name = "Package Install Service",
        .publisher = "zigos.system",
        .label = "package-service",
        .entry = "zigos.package.install",
        .components = &.{.{ .id = "package-service", .entry = "zigos.package.install" }},
        .component_class = .service_component,
        .role_tag = 0xA10E,
        .heartbeat_increment = 14,
        .contract_flags = FLAG_SYSTEM_BUNDLE,
        .service_class = .package_install_update,
    },
    .{
        .bundle_id = "zigos.system.compositor",
        .artifact_name = "userspace-compositor.elf",
        .display_name = "Compositor Session",
        .publisher = "zigos.system",
        .label = "compositor-session",
        .entry = "zigos.ui.session",
        .components = &.{.{ .id = "compositor-session", .entry = "zigos.ui.session" }},
        .component_class = .service_component,
        .role_tag = 0xA10F,
        .heartbeat_increment = 15,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_OWNS_UI_SURFACE,
        .service_class = .compositor_ui_session,
    },
    .{
        .bundle_id = "zigos.system.indexing-search",
        .artifact_name = "userspace-indexing-search.elf",
        .display_name = "Indexing Search",
        .publisher = "zigos.system",
        .label = "indexing-service",
        .entry = "zigos.index.search",
        .components = &.{.{ .id = "indexing-service", .entry = "zigos.index.search" }},
        .component_class = .service_component,
        .role_tag = 0xA110,
        .heartbeat_increment = 16,
        .contract_flags = FLAG_SYSTEM_BUNDLE,
        .service_class = .indexing_search,
    },
    .{
        .bundle_id = "zigos.system.sync-service",
        .artifact_name = "userspace-sync-service.elf",
        .display_name = "Sync Replication",
        .publisher = "zigos.system",
        .label = "sync-service",
        .entry = "zigos.sync.replication",
        .components = &.{.{ .id = "sync-service", .entry = "zigos.sync.replication" }},
        .component_class = .service_component,
        .role_tag = 0xA111,
        .heartbeat_increment = 17,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_BACKGROUND_ELIGIBLE,
        .service_class = .sync_replication,
    },
    .{
        .bundle_id = "zigos.system.media-print",
        .artifact_name = "userspace-media-print.elf",
        .display_name = "Media Print Helpers",
        .publisher = "zigos.system",
        .label = "media-print-service",
        .entry = "zigos.media.print",
        .components = &.{.{ .id = "media-print-service", .entry = "zigos.media.print" }},
        .component_class = .service_component,
        .role_tag = 0xA112,
        .heartbeat_increment = 18,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_BACKGROUND_ELIGIBLE,
        .service_class = .media_print_helpers,
    },
    .{
        .bundle_id = "zigos.system.compatibility-portal",
        .artifact_name = "userspace-compatibility-portal.elf",
        .display_name = "Compatibility Portal",
        .publisher = "zigos.system",
        .label = "compatibility-portal",
        .entry = "zigos.compat.portal",
        .components = &.{.{ .id = "compatibility-portal", .entry = "zigos.compat.portal" }},
        .component_class = .service_component,
        .role_tag = 0xA113,
        .heartbeat_increment = 19,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_COMPATIBILITY_BOUNDARY,
        .service_class = .compatibility_portal,
    },
    .{
        .bundle_id = "zigos.system.service-client",
        .artifact_name = "userspace-service-client.elf",
        .display_name = "Service Client",
        .publisher = "zigos.system",
        .label = "service-client",
        .entry = "app.service.client",
        .components = &.{.{ .id = "service-client", .entry = "app.service.client" }},
        .component_class = .app_component,
        .role_tag = 0xA114,
        .heartbeat_increment = 20,
        .contract_flags = FLAG_OWNS_UI_SURFACE,
    },
};

pub fn find(bundle_id: []const u8) ?*const ImageSpec {
    for (&boot_image_specs) |*spec| {
        if (std.mem.eql(u8, spec.bundle_id, bundle_id)) return spec;
    }
    return null;
}

pub fn contractFor(bundle_id: []const u8) ?ContractSpec {
    const spec = find(bundle_id) orelse return null;
    return contractForSpec(spec);
}

pub fn findByServiceClass(class: contract.ServiceClass) ?*const ImageSpec {
    for (&boot_image_specs) |*spec| {
        if (spec.service_class == class) return spec;
    }
    return null;
}

pub fn contractForSpec(spec: *const ImageSpec) ContractSpec {
    return .{
        .bundle_id = spec.bundle_id,
        .role_tag = spec.role_tag,
        .heartbeat_increment = spec.heartbeat_increment,
        .contract_flags = spec.contract_flags,
    };
}

test "userspace registry definitions stay unique and keep typed contract metadata attached" {
    for (boot_image_specs, 0..) |spec, index| {
        try std.testing.expect(spec.role_tag != 0);
        try std.testing.expect(spec.heartbeat_increment != 0);
        try std.testing.expect(std.mem.eql(u8, spec.source_path, "src/userspace/component_main.zig"));

        var peer_index: usize = 0;
        while (peer_index < index) : (peer_index += 1) {
            try std.testing.expect(!std.mem.eql(u8, boot_image_specs[peer_index].bundle_id, spec.bundle_id));
            try std.testing.expect(boot_image_specs[peer_index].role_tag != spec.role_tag);
        }
    }

    try std.testing.expect(findByServiceClass(.storage_object) != null);
}
