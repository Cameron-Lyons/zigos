const std = @import("std");
const contract = @import("../session/contract.zig");
const manifest = @import("../policy/manifest.zig");
const service_catalog = @import("../session/service_catalog.zig");

pub const FLAG_SYSTEM_BUNDLE: u32 = 1 << 0;
pub const FLAG_OWNS_UI_SURFACE: u32 = 1 << 1;
pub const FLAG_PERMISSION_REVIEW: u32 = 1 << 2;
pub const FLAG_BACKGROUND_ELIGIBLE: u32 = 1 << 3;
pub const FLAG_STORAGE_BOUNDARY: u32 = 1 << 4;
pub const FLAG_NETWORK_BOUNDARY: u32 = 1 << 5;
pub const FLAG_POLICY_BOUNDARY: u32 = 1 << 6;
pub const FLAG_DRIVER_BOUNDARY: u32 = 1 << 7;
pub const FLAG_COMPATIBILITY_BOUNDARY: u32 = 1 << 8;
pub const FLAG_MMU_PROOF_PROBE: u32 = 1 << 9;

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

fn serviceImageSpec(class: contract.ServiceClass, component_class: ComponentClass) ImageSpec {
    const entry = service_catalog.entryForClass(class).?;
    const image = entry.userspace_image.?;
    return .{
        .bundle_id = image.bundle_id,
        .artifact_name = image.artifact_name,
        .display_name = image.display_name,
        .publisher = image.publisher,
        .label = image.label,
        .entry = image.entry,
        .components = &.{.{ .id = image.label, .entry = image.entry }},
        .provided_interfaces = &.{entry.interface},
        .component_class = component_class,
        .role_tag = image.role_tag,
        .heartbeat_increment = image.heartbeat_increment,
        .contract_flags = image.contract_flags,
        .service_class = class,
    };
}

pub const boot_image_specs = [_]ImageSpec{
    serviceImageSpec(.session_manager, .session_manager),
    serviceImageSpec(.permission_review_ui, .service_component),
    serviceImageSpec(.service_registry, .service_component),
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
    serviceImageSpec(.policy_mediation, .service_component),
    serviceImageSpec(.network_stack, .service_component),
    serviceImageSpec(.storage_object, .service_component),
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
    serviceImageSpec(.package_install_update, .service_component),
    serviceImageSpec(.compositor_ui_session, .service_component),
    serviceImageSpec(.indexing_search, .service_component),
    serviceImageSpec(.sync_replication, .service_component),
    serviceImageSpec(.media_print_helpers, .service_component),
    serviceImageSpec(.compatibility_portal, .service_component),
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
    .{
        .bundle_id = "zigos.proof.mmu-isolation",
        .artifact_name = "userspace-mmu-isolation-proof.elf",
        .display_name = "MMU Isolation Proof",
        .publisher = "zigos.system",
        .label = "mmu-isolation-proof",
        .entry = "zigos.proof.mmu-isolation",
        .components = &.{.{ .id = "mmu-isolation-proof", .entry = "zigos.proof.mmu-isolation" }},
        .component_class = .app_component,
        .role_tag = 0xA116,
        .heartbeat_increment = 22,
        .contract_flags = FLAG_MMU_PROOF_PROBE,
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
