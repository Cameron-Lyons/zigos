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

pub const DIRECT_SERVICE_CLASS_SLOTS = true;
pub const SERVICE_CLASS_HASH_PROBES_PER_QUERY: u8 = 0;
pub const SERVICE_CLASS_COUNT: usize = std.meta.fields(contract.ServiceClass).len;
pub const ServiceClassSlotIndex = u8;
pub const RUNTIME_IMAGE_DESCRIPTORS_EXCLUDE_BUILD_METADATA = true;
pub const IMAGE_SPEC_SIZE_CEILING_BYTES: usize = 168;
const NO_SERVICE_CLASS_SLOT = std.math.maxInt(ServiceClassSlotIndex);

comptime {
    for (std.meta.fields(contract.ServiceClass), 0..) |field, class_index| {
        if (field.value != class_index) {
            @compileError("service classes must remain dense for direct userspace registry lookup");
        }
    }
}

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

pub const BuildImageSpec = struct {
    image: ImageSpec,
    artifact_name: []const u8,
    source_path: []const u8,
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

fn serviceBuildImageSpec(class: contract.ServiceClass, component_class: ComponentClass) BuildImageSpec {
    const entry = service_catalog.entryForClass(class).?;
    const catalog_image = entry.userspace_image.?;
    return .{
        .image = .{
            .bundle_id = catalog_image.bundle_id,
            .display_name = catalog_image.display_name,
            .publisher = catalog_image.publisher,
            .label = catalog_image.label,
            .entry = catalog_image.entry,
            .components = &.{.{ .id = catalog_image.label, .entry = catalog_image.entry }},
            .provided_interfaces = &.{entry.interface},
            .component_class = component_class,
            .role_tag = catalog_image.role_tag,
            .heartbeat_increment = catalog_image.heartbeat_increment,
            .contract_flags = catalog_image.contract_flags,
            .service_class = class,
            .service_kind = catalog_image.service_kind,
        },
        .artifact_name = catalog_image.artifact_name,
        .source_path = catalog_image.source_path,
    };
}

pub fn standaloneBuildImageSpec(spec: StandaloneImageSpec) BuildImageSpec {
    return .{
        .image = .{
            .bundle_id = spec.bundle_id,
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
        },
        .artifact_name = spec.artifact_name,
        .source_path = spec.source_path,
    };
}

pub const production_build_image_specs = [_]BuildImageSpec{
    serviceBuildImageSpec(.session_manager, .session_manager),
    serviceBuildImageSpec(.permission_review_ui, .service_component),
    serviceBuildImageSpec(.service_registry, .service_component),
    standaloneBuildImageSpec(.{
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
    standaloneBuildImageSpec(.{
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
    standaloneBuildImageSpec(.{
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
    standaloneBuildImageSpec(.{
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
    standaloneBuildImageSpec(.{
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
    serviceBuildImageSpec(.policy_mediation, .service_component),
    serviceBuildImageSpec(.network_stack, .service_component),
    serviceBuildImageSpec(.storage_object, .service_component),
    standaloneBuildImageSpec(.{
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
    serviceBuildImageSpec(.package_install_update, .service_component),
    serviceBuildImageSpec(.compositor_ui_session, .service_component),
    serviceBuildImageSpec(.indexing_search, .service_component),
    serviceBuildImageSpec(.personal_context, .service_component),
    serviceBuildImageSpec(.sync_replication, .service_component),
    serviceBuildImageSpec(.media_print_helpers, .service_component),
    serviceBuildImageSpec(.attention_broker, .service_component),
    serviceBuildImageSpec(.task_lifecycle, .service_component),
    serviceBuildImageSpec(.sensitive_capture, .service_component),
    serviceBuildImageSpec(.secure_pasteboard, .service_component),
    serviceBuildImageSpec(.object_resilience, .service_component),
    serviceBuildImageSpec(.secret_vault, .service_component),
};

pub const production_boot_image_specs = runtimeImageSpecs(production_build_image_specs);

pub fn runtimeImageSpecs(comptime build_specs: anytype) [build_specs.len]ImageSpec {
    var runtime_specs: [build_specs.len]ImageSpec = undefined;
    for (build_specs, 0..) |spec, index| runtime_specs[index] = spec.image;
    return runtime_specs;
}

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
const ServiceClassSlots = [SERVICE_CLASS_COUNT]ServiceClassSlotIndex;
const service_class_slots = buildServiceClassSlots();

pub const userspace_registry_indexing = .{
    .uses_bundle_id_index = @TypeOf(production_bundle_index) == id_index.Table(PRODUCTION_BUNDLE_INDEX_CAPACITY),
    .uses_service_class_slots = @TypeOf(service_class_slots) == ServiceClassSlots,
    .service_class_hash_probes_per_query = SERVICE_CLASS_HASH_PROBES_PER_QUERY,
    .service_class_slot_bytes = @sizeOf(ServiceClassSlots),
};

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
    const spec_index = publicServiceClassSlot(service_class_slots[serviceClassIndex(class)]) orelse {
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

fn buildServiceClassSlots() ServiceClassSlots {
    var slots = emptyServiceClassSlots();
    for (production_boot_image_specs, 0..) |spec, spec_index| {
        const class = spec.service_class orelse continue;
        setServiceClassSlot(&slots, class, spec_index);
    }
    return slots;
}

fn emptyServiceClassSlots() ServiceClassSlots {
    return [_]ServiceClassSlotIndex{NO_SERVICE_CLASS_SLOT} ** SERVICE_CLASS_COUNT;
}

fn setServiceClassSlot(slots: *ServiceClassSlots, class: contract.ServiceClass, spec_index: usize) void {
    if (spec_index >= NO_SERVICE_CLASS_SLOT) @compileError("userspace service class slot exceeds compact range");
    const class_index = serviceClassIndex(class);
    if (slots[class_index] != NO_SERVICE_CLASS_SLOT) @compileError("userspace registry contains duplicate service classes");
    slots[class_index] = @intCast(spec_index);
}

fn serviceClassIndex(class: contract.ServiceClass) usize {
    return @intFromEnum(class);
}

fn publicServiceClassSlot(slot: ServiceClassSlotIndex) ?usize {
    return if (slot == NO_SERVICE_CLASS_SLOT) null else slot;
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

fn buildImageByServiceClass(class: contract.ServiceClass) ?*const BuildImageSpec {
    const spec_index = publicServiceClassSlot(service_class_slots[serviceClassIndex(class)]) orelse return null;
    return &production_build_image_specs[spec_index];
}

test "userspace registry definitions stay unique and keep typed contract metadata attached" {
    try std.testing.expect(DIRECT_SERVICE_CLASS_SLOTS);
    try std.testing.expectEqual(@as(u8, 0), SERVICE_CLASS_HASH_PROBES_PER_QUERY);
    try std.testing.expectEqual(@as(usize, SERVICE_CLASS_COUNT), userspace_registry_indexing.service_class_slot_bytes);
    try std.testing.expect(RUNTIME_IMAGE_DESCRIPTORS_EXCLUDE_BUILD_METADATA);
    try std.testing.expect(!@hasField(ImageSpec, "artifact_name"));
    try std.testing.expect(!@hasField(ImageSpec, "source_path"));
    try std.testing.expect(@sizeOf(ImageSpec) <= IMAGE_SPEC_SIZE_CEILING_BYTES);
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
    try std.testing.expect(findByServiceClass(.task_runtime) == null);
}

test "core platform services use the parameterized userspace service entrypoint" {
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.storage_object).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.storage, findByServiceClass(.storage_object).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.sync_replication).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.sync, findByServiceClass(.sync_replication).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.network_stack).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.network, findByServiceClass(.network_stack).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.package_install_update).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.package, findByServiceClass(.package_install_update).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.compositor_ui_session).?.source_path);
    try std.testing.expectEqual(userspace_mailbox.ServiceKind.compositor, findByServiceClass(.compositor_ui_session).?.service_kind);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.attention_broker).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.task_lifecycle).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.sensitive_capture).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.secure_pasteboard).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.object_resilience).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.secret_vault).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/component_main.zig", buildImageByServiceClass(.policy_mediation).?.source_path);
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
