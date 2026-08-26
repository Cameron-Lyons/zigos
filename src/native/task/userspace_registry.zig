const std = @import("std");
const contract = @import("../session/contract.zig");
const component_abi_schema = @import("../services/component_abi_schema.zig");
const id_index = @import("../core/id_index.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const service_catalog = @import("../session/service_catalog.zig");
const userspace_mailbox = @import("userspace_bootstrap_mailbox.zig");
const userspace_flags = @import("userspace_flags.zig");

pub const FLAG_SYSTEM_BUNDLE = userspace_flags.FLAG_SYSTEM_BUNDLE;
pub const FLAG_OWNS_UI_SURFACE = userspace_flags.FLAG_OWNS_UI_SURFACE;
pub const FLAG_PERMISSION_REVIEW = userspace_flags.FLAG_PERMISSION_REVIEW;
pub const FLAG_BACKGROUND_ELIGIBLE = userspace_flags.FLAG_BACKGROUND_ELIGIBLE;
pub const FLAG_STORAGE_BOUNDARY = userspace_flags.FLAG_STORAGE_BOUNDARY;
pub const FLAG_NETWORK_BOUNDARY = userspace_flags.FLAG_NETWORK_BOUNDARY;
pub const FLAG_POLICY_BOUNDARY = userspace_flags.FLAG_POLICY_BOUNDARY;
pub const FLAG_DRIVER_BOUNDARY = userspace_flags.FLAG_DRIVER_BOUNDARY;
pub const FLAG_MMU_PROOF_PROBE = userspace_flags.FLAG_MMU_PROOF_PROBE;
pub const FLAG_NX_PROOF_PROBE = userspace_flags.FLAG_NX_PROOF_PROBE;
pub const FLAG_GP_PROOF_PROBE = userspace_flags.FLAG_GP_PROOF_PROBE;

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
    service_kind: userspace_mailbox.ServiceKind = .generic,
};

pub const StandaloneImageSpec = struct {
    bundle_id: []const u8,
    artifact_name: []const u8,
    source_path: []const u8 = "src/userspace/component_main.zig",
    display_name: []const u8,
    publisher: []const u8 = "zigos.system",
    label: []const u8,
    entry: []const u8,
    provided_interfaces: []const manifest.InterfaceDecl = &.{},
    consumed_interfaces: []const manifest.InterfaceDecl = &.{},
    assets: []const manifest.AssetDecl = &.{},
    update_channel: manifest.UpdateChannel = .stable,
    component_class: ComponentClass = .app_component,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32 = 0,
};

fn serviceImageSpec(class: contract.ServiceClass, component_class: ComponentClass) ImageSpec {
    const entry = service_catalog.entryForClass(class).?;
    const image = entry.userspace_image.?;
    return .{
        .bundle_id = image.bundle_id,
        .artifact_name = image.artifact_name,
        .source_path = image.source_path,
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
        .service_kind = image.service_kind,
    };
}

pub fn standaloneImageSpec(spec: StandaloneImageSpec) ImageSpec {
    return .{
        .bundle_id = spec.bundle_id,
        .artifact_name = spec.artifact_name,
        .source_path = spec.source_path,
        .display_name = spec.display_name,
        .publisher = spec.publisher,
        .label = spec.label,
        .entry = spec.entry,
        .components = &.{.{ .id = spec.label, .entry = spec.entry }},
        .provided_interfaces = spec.provided_interfaces,
        .consumed_interfaces = spec.consumed_interfaces,
        .assets = spec.assets,
        .update_channel = spec.update_channel,
        .component_class = spec.component_class,
        .role_tag = spec.role_tag,
        .heartbeat_increment = spec.heartbeat_increment,
        .contract_flags = spec.contract_flags,
    };
}

pub const production_boot_image_specs = [_]ImageSpec{
    serviceImageSpec(.session_manager, .session_manager),
    serviceImageSpec(.permission_review_ui, .service_component),
    serviceImageSpec(.service_registry, .service_component),
    standaloneImageSpec(.{
        .bundle_id = "zigos.system.workspace-storage",
        .artifact_name = "userspace-workspace-storage.elf",
        .display_name = "Workspace Storage",
        .label = "workspace-storage",
        .entry = "zigos.bootstrap.workspace",
        .component_class = .service_component,
        .role_tag = 0xA103,
        .heartbeat_increment = 3,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_STORAGE_BOUNDARY,
    }),
    standaloneImageSpec(.{
        .bundle_id = "app.viewer",
        .artifact_name = "userspace-viewer.elf",
        .display_name = "Viewer",
        .publisher = "zigos.dev",
        .label = "viewer",
        .entry = "app.viewer",
        .provided_interfaces = &.{.{ .name = "zigos.viewer.document" }},
        .consumed_interfaces = &.{component_abi_schema.interfaceDecl(.object_workspace)},
        .assets = &.{.{ .path = "assets/viewer/icon.svg", .content_type = "image/svg+xml" }},
        .role_tag = 0xA106,
        .heartbeat_increment = 6,
        .contract_flags = FLAG_OWNS_UI_SURFACE,
    }),
    standaloneImageSpec(.{
        .bundle_id = "app.notes",
        .artifact_name = "userspace-notes.elf",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .label = "notes",
        .entry = "app.notes",
        .provided_interfaces = &.{.{ .name = "zigos.workspace.document" }},
        .consumed_interfaces = &.{component_abi_schema.interfaceDecl(.object_workspace)},
        .assets = &.{.{ .path = "assets/notes/icon.svg", .content_type = "image/svg+xml" }},
        .update_channel = .beta,
        .role_tag = 0xA107,
        .heartbeat_increment = 7,
        .contract_flags = FLAG_OWNS_UI_SURFACE,
    }),
    standaloneImageSpec(.{
        .bundle_id = "app.sync",
        .artifact_name = "userspace-sync.elf",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .label = "sync",
        .entry = "app.sync",
        .provided_interfaces = &.{component_abi_schema.interfaceDecl(.sync_replication)},
        .consumed_interfaces = &.{component_abi_schema.interfaceDecl(.object_workspace)},
        .assets = &.{.{ .path = "assets/sync/icon.svg", .content_type = "image/svg+xml" }},
        .role_tag = 0xA108,
        .heartbeat_increment = 8,
        .contract_flags = FLAG_BACKGROUND_ELIGIBLE,
    }),
    standaloneImageSpec(.{
        .bundle_id = "app.capture",
        .artifact_name = "userspace-capture.elf",
        .display_name = "Capture",
        .publisher = "zigos.dev",
        .label = "capture",
        .entry = "app.capture",
        .provided_interfaces = &.{.{ .name = "zigos.capture.session" }},
        .consumed_interfaces = &.{component_abi_schema.interfaceDecl(.media_print)},
        .assets = &.{.{ .path = "assets/capture/icon.svg", .content_type = "image/svg+xml" }},
        .role_tag = 0xA109,
        .heartbeat_increment = 9,
        .contract_flags = FLAG_OWNS_UI_SURFACE,
    }),
    serviceImageSpec(.policy_mediation, .service_component),
    serviceImageSpec(.network_stack, .service_component),
    serviceImageSpec(.storage_object, .service_component),
    standaloneImageSpec(.{
        .bundle_id = "zigos.system.storage-driver",
        .artifact_name = "userspace-storage-driver.elf",
        .display_name = "Storage Driver",
        .label = "storage-driver",
        .entry = "zigos.driver.storage",
        .component_class = .service_component,
        .role_tag = 0xA10D,
        .heartbeat_increment = 13,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_DRIVER_BOUNDARY | FLAG_STORAGE_BOUNDARY,
    }),
    serviceImageSpec(.package_install_update, .service_component),
    serviceImageSpec(.compositor_ui_session, .service_component),
    serviceImageSpec(.indexing_search, .service_component),
    serviceImageSpec(.personal_context, .service_component),
    serviceImageSpec(.sync_replication, .service_component),
    serviceImageSpec(.media_print_helpers, .service_component),
    serviceImageSpec(.attention_broker, .service_component),
    serviceImageSpec(.task_lifecycle, .service_component),
    serviceImageSpec(.sensitive_capture, .service_component),
    serviceImageSpec(.secure_pasteboard, .service_component),
    serviceImageSpec(.object_resilience, .service_component),
    serviceImageSpec(.secret_vault, .service_component),
};

pub const role_boot_image_specs = production_boot_image_specs;

comptime {
    if (production_boot_image_specs.len != 24) {
        @compileError("production userspace catalog must contain exactly 24 images");
    }
    for (production_boot_image_specs) |spec| {
        if ((spec.contract_flags & (FLAG_MMU_PROOF_PROBE | FLAG_NX_PROOF_PROBE)) != 0) {
            @compileError("production userspace catalog cannot enable MMU verification probes");
        }
    }
}

const PRODUCTION_BUNDLE_INDEX_CAPACITY: usize = production_boot_image_specs.len * 2;
const production_bundle_index = buildBundleIndex(
    PRODUCTION_BUNDLE_INDEX_CAPACITY,
    &production_boot_image_specs,
);
const SERVICE_CLASS_INDEX_CAPACITY: usize = production_boot_image_specs.len * 2;
const service_class_index = buildServiceClassIndex();

pub fn findProduction(bundle_id: []const u8) ?*const ImageSpec {
    const spec_index = indexInCatalog(
        PRODUCTION_BUNDLE_INDEX_CAPACITY,
        &production_boot_image_specs,
        &production_bundle_index,
        bundle_id,
    ) orelse return null;
    return &production_boot_image_specs[spec_index];
}

pub fn findForRole(bundle_id: []const u8) ?*const ImageSpec {
    return findProduction(bundle_id);
}

pub fn indexForRole(bundle_id: []const u8) ?usize {
    return indexInCatalog(
        PRODUCTION_BUNDLE_INDEX_CAPACITY,
        &production_boot_image_specs,
        &production_bundle_index,
        bundle_id,
    );
}

fn indexInCatalog(
    comptime capacity: usize,
    specs: []const ImageSpec,
    index: *const id_index.Table(capacity),
    bundle_id: []const u8,
) ?usize {
    const key = bundleIndexKey(bundle_id);
    const spec_index = id_index.lookup(capacity, index, key) orelse {
        debugAssertBundleIndexMissAbsent(specs, bundle_id);
        return null;
    };
    if (spec_index >= specs.len) {
        native_util.impossibleByInvariant("boot bundle id index points outside registry specs");
    }
    if (!std.mem.eql(u8, specs[spec_index].bundle_id, bundle_id)) {
        native_util.impossibleByInvariant("boot bundle id index points at the wrong registry spec");
    }
    return spec_index;
}

pub fn productionContractFor(bundle_id: []const u8) ?ContractSpec {
    const spec = findProduction(bundle_id) orelse return null;
    return contractForSpec(spec);
}

pub fn findByServiceClass(class: contract.ServiceClass) ?*const ImageSpec {
    const key = serviceClassIndexKey(class);
    const spec_index = id_index.lookup(SERVICE_CLASS_INDEX_CAPACITY, &service_class_index, key) orelse {
        debugAssertServiceClassIndexMissAbsent(class);
        return null;
    };
    if (spec_index >= production_boot_image_specs.len) {
        native_util.impossibleByInvariant("boot service class index points outside registry specs");
    }
    const spec = &production_boot_image_specs[spec_index];
    if (spec.service_class) |spec_class| {
        if (spec_class != class) {
            native_util.impossibleByInvariant("boot service class index points at the wrong registry spec");
        }
    } else {
        native_util.impossibleByInvariant("boot service class index points at a non-service registry spec");
    }
    return spec;
}

pub fn contractForSpec(spec: *const ImageSpec) ContractSpec {
    return .{
        .bundle_id = spec.bundle_id,
        .role_tag = spec.role_tag,
        .heartbeat_increment = spec.heartbeat_increment,
        .contract_flags = spec.contract_flags,
    };
}

pub fn bundleIndexKey(bundle_id: []const u8) u64 {
    const hash = native_util.fnv1a64(bundle_id);
    return if (hash == 0) 1 else hash;
}

pub fn serviceClassIndexKey(class: contract.ServiceClass) u64 {
    return @as(u64, @intFromEnum(class)) + 1;
}

fn buildBundleIndex(
    comptime capacity: usize,
    comptime specs: []const ImageSpec,
) id_index.Table(capacity) {
    @setEvalBranchQuota(10_000);
    var index = id_index.emptyTable(capacity);
    for (specs, 0..) |spec, spec_index| {
        id_index.insert(capacity, &index, bundleIndexKey(spec.bundle_id), spec_index, "boot bundle id index covers userspace registry");
    }
    return index;
}

fn debugAssertBundleIndexMissAbsent(specs: []const ImageSpec, bundle_id: []const u8) void {
    if (@import("builtin").mode != .Debug) return;
    for (specs) |spec| {
        if (std.mem.eql(u8, spec.bundle_id, bundle_id)) {
            native_util.impossibleByInvariant("boot bundle id index missed a registry spec");
        }
    }
}

fn buildServiceClassIndex() id_index.Table(SERVICE_CLASS_INDEX_CAPACITY) {
    @setEvalBranchQuota(10_000);
    var index = id_index.emptyTable(SERVICE_CLASS_INDEX_CAPACITY);
    for (production_boot_image_specs, 0..) |spec, spec_index| {
        const class = spec.service_class orelse continue;
        id_index.insert(SERVICE_CLASS_INDEX_CAPACITY, &index, serviceClassIndexKey(class), spec_index, "boot service class index covers userspace registry");
    }
    return index;
}

fn debugAssertServiceClassIndexMissAbsent(class: contract.ServiceClass) void {
    if (@import("builtin").mode != .Debug) return;
    for (production_boot_image_specs) |spec| {
        if (spec.service_class) |spec_class| {
            if (spec_class == class) {
                native_util.impossibleByInvariant("boot service class index missed a registry spec");
            }
        }
    }
}

test "userspace registry definitions stay unique and keep typed contract metadata attached" {
    for (production_boot_image_specs, 0..) |spec, index| {
        try std.testing.expect(spec.role_tag != 0);
        try std.testing.expect(spec.heartbeat_increment != 0);
        try std.testing.expectEqual(index, indexForRole(spec.bundle_id).?);
        if (spec.service_class) |class| {
            const indexed = findByServiceClass(class) orelse return error.MissingServiceClassIndexEntry;
            try std.testing.expectEqualStrings(spec.bundle_id, indexed.bundle_id);
        }

        var peer_index: usize = 0;
        while (peer_index < index) : (peer_index += 1) {
            try std.testing.expect(!std.mem.eql(u8, production_boot_image_specs[peer_index].bundle_id, spec.bundle_id));
            try std.testing.expect(production_boot_image_specs[peer_index].role_tag != spec.role_tag);
            if (spec.service_class) |class| {
                if (production_boot_image_specs[peer_index].service_class) |peer_class| {
                    try std.testing.expect(peer_class != class);
                }
            }
        }
    }

    try std.testing.expect(findByServiceClass(.storage_object) != null);
}

test "core platform services use the parameterized userspace service entrypoint" {
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.storage_object).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.storage, findByServiceClass(.storage_object).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.sync_replication).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.sync, findByServiceClass(.sync_replication).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.network_stack).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.network, findByServiceClass(.network_stack).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.package_install_update).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.package, findByServiceClass(.package_install_update).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.compositor_ui_session).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.compositor, findByServiceClass(.compositor_ui_session).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.attention_broker).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.task_lifecycle).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.sensitive_capture).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.secure_pasteboard).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.object_resilience).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", findByServiceClass(.secret_vault).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/component_main.zig", findByServiceClass(.policy_mediation).?.source_path);
}

test "production userspace registry contains exactly the production boot catalog" {
    try std.testing.expectEqual(@as(usize, 24), production_boot_image_specs.len);

    for (production_boot_image_specs) |spec| {
        const production_spec = findProduction(spec.bundle_id) orelse return error.MissingProductionImage;
        try std.testing.expectEqualStrings(spec.bundle_id, production_spec.bundle_id);
        try std.testing.expectEqual(@as(u32, 0), spec.contract_flags & FLAG_MMU_PROOF_PROBE);
    }
    try std.testing.expect(findProduction("app.notes.daily") == null);
}
