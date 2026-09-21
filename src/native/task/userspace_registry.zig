const std = @import("std");
const contract = @import("../session/contract.zig");
const component_abi_schema = @import("../services/component_abi_schema.zig");
const id_index = @import("../core/id_index.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const service_catalog = @import("../session/service_catalog.zig");
const userspace_mailbox = @import("userspace_bootstrap_mailbox.zig");
const userspace_layout = @import("../core/userspace_layout.zig");
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
pub const SINGLE_COMPONENT_BOOT_MANIFESTS_DERIVED_ON_REGISTRATION = true;
pub const RUNTIME_IMAGE_DESCRIPTORS_OMIT_BUILD_LOOKUP_METADATA = true;
pub const COMPACT_RUNTIME_IMAGE_CONTRACT_METADATA = true;
pub const RUNTIME_IMAGE_DESCRIPTORS_USE_COMPACT_PUBLISHERS = true;
pub const RUNTIME_IMAGE_DESCRIPTORS_USE_OPTIONAL_MANIFEST_DECLS = true;
pub const RUNTIME_IMAGE_DESCRIPTORS_USE_SENTINEL_BOOT_STRINGS = true;
pub const RUNTIME_IMAGE_DESCRIPTORS_USE_PACKED_METADATA = true;
pub const RuntimeBundleIdLength = u6;
pub const RuntimeRoleTag = u16;
pub const RuntimeHeartbeatIncrement = u5;
pub const RuntimeContractFlags = u12;
pub const RuntimeUpdateChannel = u2;
pub const RuntimeComponentClass = u2;
pub const RuntimePublisher = u1;
pub const IMAGE_SPEC_SIZE_CEILING_BYTES: usize = 64;
pub const PRODUCTION_ADDRESS_SPACE_COUNT: usize = 6;
pub const COLOCATES_SERVICES_BY_ADDRESS_SPACE_GROUP = true;
pub const SHARES_GROUP_PAGE_TABLES = true;
pub const USES_PKU_WITHIN_GROUP = true;

pub const AddressSpaceGroup = enum(u8) {
    session,
    drivers,
    store,
    notes,
    privacy,
    apps,
};
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

pub const Publisher = enum(u8) {
    system,
    development,

    pub fn fromName(publisher_name: []const u8) ?Publisher {
        if (std.mem.eql(u8, publisher_name, "zigos.system")) return .system;
        if (std.mem.eql(u8, publisher_name, "zigos.dev")) return .development;
        return null;
    }

    pub fn name(self: Publisher) []const u8 {
        return switch (self) {
            .system => "zigos.system",
            .development => "zigos.dev",
        };
    }
};

pub const ContractSpec = struct {
    bundle_id: []const u8,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32,
};

pub const RuntimeImageMetadata = packed struct(u64) {
    bundle_id_len: RuntimeBundleIdLength,
    role_tag: RuntimeRoleTag,
    heartbeat_increment: RuntimeHeartbeatIncrement,
    contract_flags: RuntimeContractFlags,
    update_channel: RuntimeUpdateChannel,
    component_class: RuntimeComponentClass,
    publisher: RuntimePublisher,
    reserved: u20 = 0,
};

pub const ImageSpec = struct {
    bundle_id: [*]const u8,
    display_name: [*:0]const u8,
    label: [*:0]const u8,
    entry: [*:0]const u8,
    provided_interface: ?*const [1]manifest.InterfaceDecl = null,
    consumed_interface: ?*const [1]manifest.InterfaceDecl = null,
    asset: ?*const [1]manifest.AssetDecl = null,
    metadata: RuntimeImageMetadata,

    pub fn bundleId(self: *const ImageSpec) []const u8 {
        return self.bundle_id[0..self.metadata.bundle_id_len];
    }

    pub fn publisher(self: *const ImageSpec) Publisher {
        return @enumFromInt(self.metadata.publisher);
    }

    pub fn updateChannel(self: *const ImageSpec) manifest.UpdateChannel {
        return @enumFromInt(self.metadata.update_channel);
    }

    pub fn componentClass(self: *const ImageSpec) ComponentClass {
        return @enumFromInt(self.metadata.component_class);
    }

    pub fn roleTag(self: *const ImageSpec) u32 {
        return self.metadata.role_tag;
    }

    pub fn heartbeatIncrement(self: *const ImageSpec) u32 {
        return self.metadata.heartbeat_increment;
    }

    pub fn contractFlags(self: *const ImageSpec) u32 {
        return self.metadata.contract_flags;
    }

    pub fn providedInterfaces(self: *const ImageSpec) []const manifest.InterfaceDecl {
        return optionalManifestDecls(manifest.InterfaceDecl, self.provided_interface);
    }

    pub fn consumedInterfaces(self: *const ImageSpec) []const manifest.InterfaceDecl {
        return optionalManifestDecls(manifest.InterfaceDecl, self.consumed_interface);
    }

    pub fn assets(self: *const ImageSpec) []const manifest.AssetDecl {
        return optionalManifestDecls(manifest.AssetDecl, self.asset);
    }

    pub fn displayName(self: *const ImageSpec) []const u8 {
        return std.mem.span(self.display_name);
    }

    pub fn componentLabel(self: *const ImageSpec) []const u8 {
        return std.mem.span(self.label);
    }

    pub fn entryName(self: *const ImageSpec) []const u8 {
        return std.mem.span(self.entry);
    }
};

pub const BuildImageSpec = struct {
    image: ImageSpec,
    artifact_name: []const u8,
    source_path: []const u8,
    service_class: ?contract.ServiceClass = null,
    service_kind: userspace_mailbox.ServiceKind = .generic,
};

pub const StandaloneImageSpec = struct {
    bundle_id: []const u8,
    artifact_name: []const u8,
    source_path: []const u8 = "src/userspace/component_main.zig",
    display_name: [:0]const u8,
    publisher: Publisher = .system,
    label: [:0]const u8,
    entry: [:0]const u8,
    provided_interfaces: []const manifest.InterfaceDecl = &.{},
    consumed_interfaces: []const manifest.InterfaceDecl = &.{},
    assets: []const manifest.AssetDecl = &.{},
    update_channel: manifest.UpdateChannel = .stable,
    component_class: ComponentClass = .app_component,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32 = 0,
};

fn serviceBuildImageSpec(comptime class: contract.ServiceClass, comptime component_class: ComponentClass) BuildImageSpec {
    const entry = service_catalog.entryForClass(class).?;
    const catalog_image = entry.userspace_image.?;
    const publisher = Publisher.fromName(catalog_image.publisher) orelse
        @compileError("userspace service publisher is not represented by the runtime catalog");
    return .{
        .image = .{
            .bundle_id = catalog_image.bundle_id.ptr,
            .display_name = catalog_image.display_name.ptr,
            .label = catalog_image.label.ptr,
            .entry = catalog_image.entry.ptr,
            .provided_interface = optionalManifestDecl(manifest.InterfaceDecl, &.{entry.interface}, "provided interfaces"),
            .metadata = runtimeImageMetadata(
                catalog_image.bundle_id,
                publisher,
                .stable,
                component_class,
                catalog_image.role_tag,
                catalog_image.heartbeat_increment,
                catalog_image.contract_flags,
            ),
        },
        .artifact_name = catalog_image.artifact_name,
        .source_path = catalog_image.source_path,
        .service_class = class,
        .service_kind = catalog_image.service_kind,
    };
}

pub fn standaloneBuildImageSpec(comptime spec: StandaloneImageSpec) BuildImageSpec {
    return .{
        .image = .{
            .bundle_id = spec.bundle_id.ptr,
            .display_name = spec.display_name.ptr,
            .label = spec.label.ptr,
            .entry = spec.entry.ptr,
            .provided_interface = optionalManifestDecl(manifest.InterfaceDecl, spec.provided_interfaces, "provided interfaces"),
            .consumed_interface = optionalManifestDecl(manifest.InterfaceDecl, spec.consumed_interfaces, "consumed interfaces"),
            .asset = optionalManifestDecl(manifest.AssetDecl, spec.assets, "assets"),
            .metadata = runtimeImageMetadata(
                spec.bundle_id,
                spec.publisher,
                spec.update_channel,
                spec.component_class,
                spec.role_tag,
                spec.heartbeat_increment,
                spec.contract_flags,
            ),
        },
        .artifact_name = spec.artifact_name,
        .source_path = spec.source_path,
    };
}

pub const production_build_image_specs = [_]BuildImageSpec{
    standaloneBuildImageSpec(.{
        .bundle_id = "zigos.system.session",
        .artifact_name = "userspace-session.elf",
        .source_path = "src/userspace/service_main.zig",
        .display_name = "Session",
        .label = "session",
        .entry = "zigos.session.manager",
        .provided_interfaces = &.{component_abi_schema.interfaceDecl(.session_manager)},
        .component_class = .session_manager,
        .role_tag = 0xA101,
        .heartbeat_increment = 1,
        .contract_flags = FLAG_SYSTEM_BUNDLE,
    }),
    standaloneBuildImageSpec(.{
        .bundle_id = "zigos.system.drivers",
        .artifact_name = "userspace-drivers.elf",
        .source_path = "src/userspace/service_main.zig",
        .display_name = "Drivers",
        .label = "drivers",
        .entry = "zigos.driver.storage",
        .provided_interfaces = &.{component_abi_schema.interfaceDecl(.network_policy)},
        .component_class = .service_component,
        .role_tag = 0xA10D,
        .heartbeat_increment = 13,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_OWNS_UI_SURFACE | FLAG_DRIVER_BOUNDARY | FLAG_STORAGE_BOUNDARY | FLAG_NETWORK_BOUNDARY,
    }),
    standaloneBuildImageSpec(.{
        .bundle_id = "zigos.system.store",
        .artifact_name = "userspace-store.elf",
        .source_path = "src/userspace/service_main.zig",
        .display_name = "Object Store",
        .label = "store",
        .entry = "zigos.bootstrap.workspace",
        .provided_interfaces = &.{component_abi_schema.interfaceDecl(.object_workspace)},
        .component_class = .service_component,
        .role_tag = 0xA103,
        .heartbeat_increment = 3,
        .contract_flags = FLAG_SYSTEM_BUNDLE | FLAG_STORAGE_BOUNDARY,
    }),
    standaloneBuildImageSpec(.{
        .bundle_id = "app.notes",
        .artifact_name = "userspace-notes.elf",
        .display_name = "Notes",
        .publisher = .development,
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
        .bundle_id = "zigos.system.privacy",
        .artifact_name = "userspace-privacy.elf",
        .source_path = "src/userspace/service_main.zig",
        .display_name = "Privacy",
        .label = "privacy",
        .entry = "zigos.secret.vault",
        .provided_interfaces = &.{component_abi_schema.interfaceDecl(.secret_vault)},
        .component_class = .service_component,
        .role_tag = 0xA115,
        .heartbeat_increment = 21,
        .contract_flags = FLAG_SYSTEM_BUNDLE,
    }),
    standaloneBuildImageSpec(.{
        .bundle_id = "zigos.system.apps",
        .artifact_name = "userspace-apps.elf",
        .display_name = "Apps",
        .publisher = .development,
        .label = "apps",
        .entry = "app.viewer",
        .provided_interfaces = &.{.{ .name = "zigos.viewer.document" }},
        .consumed_interfaces = &.{component_abi_schema.interfaceDecl(.object_workspace)},
        .assets = &.{.{ .path = "assets/viewer/icon.svg", .content_type = "image/svg+xml" }},
        .role_tag = 0xA106,
        .heartbeat_increment = 6,
        .contract_flags = FLAG_OWNS_UI_SURFACE,
    }),
};

pub const production_boot_image_specs = runtimeImageSpecs(production_build_image_specs);

pub fn runtimeImageSpecs(comptime build_specs: anytype) [build_specs.len]ImageSpec {
    var runtime_specs: [build_specs.len]ImageSpec = undefined;
    for (build_specs, 0..) |spec, index| runtime_specs[index] = spec.image;
    return runtime_specs;
}

fn runtimeImageMetadata(
    comptime bundle_id: []const u8,
    comptime publisher: Publisher,
    comptime update_channel: manifest.UpdateChannel,
    comptime component_class: ComponentClass,
    comptime role_tag: u32,
    comptime heartbeat_increment: u32,
    comptime contract_flags: u32,
) RuntimeImageMetadata {
    return .{
        .bundle_id_len = @intCast(bundle_id.len),
        .role_tag = @intCast(role_tag),
        .heartbeat_increment = @intCast(heartbeat_increment),
        .contract_flags = @intCast(contract_flags),
        .update_channel = @intCast(@intFromEnum(update_channel)),
        .component_class = @intCast(@intFromEnum(component_class)),
        .publisher = @intCast(@intFromEnum(publisher)),
    };
}

fn optionalManifestDecl(
    comptime Decl: type,
    comptime decls: []const Decl,
    comptime description: []const u8,
) ?*const [1]Decl {
    if (decls.len > 1) {
        @compileError("runtime image catalog supports at most one " ++ description ++ " declaration");
    }
    return if (decls.len == 1) &.{decls[0]} else null;
}

fn optionalManifestDecls(comptime Decl: type, decl: ?*const [1]Decl) []const Decl {
    return decl orelse &.{};
}

pub const role_boot_image_specs = production_boot_image_specs;

comptime {
    if (production_boot_image_specs.len != 6) {
        @compileError("production userspace catalog must contain exactly 6 images");
    }
    if (std.meta.fields(AddressSpaceGroup).len != PRODUCTION_ADDRESS_SPACE_COUNT) {
        @compileError("production address-space groups must match the 2026 process count");
    }
    for (production_boot_image_specs) |spec| {
        if ((spec.contractFlags() & (FLAG_MMU_PROOF_PROBE | FLAG_NX_PROOF_PROBE)) != 0) {
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
    if (!std.mem.eql(u8, specs[spec_index].bundleId(), bundle_id)) {
        native_util.impossibleByInvariant("boot bundle id index points at the wrong registry spec");
    }
    return spec_index;
}

pub fn productionContractFor(bundle_id: []const u8) ?ContractSpec {
    const spec = findProduction(bundle_id) orelse return null;
    return contractForSpec(spec);
}

pub fn addressSpaceGroupForServiceClass(class: contract.ServiceClass) ?AddressSpaceGroup {
    return switch (class) {
        .session_manager,
        .policy_mediation,
        .permission_review_ui,
        .attention_broker,
        .task_lifecycle,
        .service_registry,
        => .session,
        .network_stack, .compositor_ui_session => .drivers,
        .storage_object,
        .package_install_update,
        .indexing_search,
        .sync_replication,
        .object_resilience,
        => .store,
        .secret_vault,
        .secure_pasteboard,
        .sensitive_capture,
        .personal_context,
        => .privacy,
        .media_print_helpers => .apps,
        .task_runtime => null,
    };
}

pub fn addressSpaceGroupForBundle(bundle_id: []const u8) ?AddressSpaceGroup {
    for (production_build_image_specs) |spec| {
        if (!std.mem.eql(u8, spec.image.bundleId(), bundle_id)) continue;
        if (spec.service_class) |class| return addressSpaceGroupForServiceClass(class);
        return standaloneAddressSpaceGroup(bundle_id);
    }
    return standaloneAddressSpaceGroup(bundle_id);
}

pub fn canonicalProductionBundleId(bundle_id: []const u8) []const u8 {
    const group = addressSpaceGroupForBundle(bundle_id) orelse return bundle_id;
    return production_boot_image_specs[@intFromEnum(group)].bundleId();
}

fn standaloneAddressSpaceGroup(bundle_id: []const u8) ?AddressSpaceGroup {
    if (std.mem.eql(u8, bundle_id, "zigos.system.store") or
        std.mem.eql(u8, bundle_id, "zigos.system.workspace-storage") or
        std.mem.eql(u8, bundle_id, "zigos.system.storage-object") or
        std.mem.eql(u8, bundle_id, "zigos.system.sync-service") or
        std.mem.eql(u8, bundle_id, "app.sync"))
        return .store;
    if (std.mem.eql(u8, bundle_id, "zigos.system.drivers") or
        std.mem.eql(u8, bundle_id, "zigos.system.storage-driver") or
        std.mem.eql(u8, bundle_id, "zigos.system.network-stack") or
        std.mem.eql(u8, bundle_id, "zigos.system.compositor"))
        return .drivers;
    if (std.mem.eql(u8, bundle_id, "zigos.system.session") or
        std.mem.eql(u8, bundle_id, "zigos.system.session-manager") or
        std.mem.eql(u8, bundle_id, "zigos.system.service-registry"))
        return .session;
    if (std.mem.eql(u8, bundle_id, "app.notes")) return .notes;
    if (std.mem.eql(u8, bundle_id, "zigos.system.privacy") or
        std.mem.eql(u8, bundle_id, "zigos.system.secret-vault") or
        std.mem.eql(u8, bundle_id, "app.capture"))
        return .privacy;
    if (std.mem.eql(u8, bundle_id, "zigos.system.apps") or
        std.mem.eql(u8, bundle_id, "zigos.system.media-print") or
        std.mem.eql(u8, bundle_id, "app.viewer"))
        return .apps;
    return null;
}

pub fn imageSlotInGroup(bundle_id: []const u8) ?u8 {
    const group = addressSpaceGroupForBundle(bundle_id) orelse return null;
    var slot: u8 = 0;
    for (production_build_image_specs) |spec| {
        const spec_id = spec.image.bundleId();
        const spec_group = addressSpaceGroupForBundle(spec_id) orelse continue;
        if (spec_group != group) continue;
        if (std.mem.eql(u8, spec_id, bundle_id)) return slot;
        slot += 1;
    }
    return null;
}

pub fn imageBaseForBundle(bundle_id: []const u8) u64 {
    const slot = imageSlotInGroup(bundle_id) orelse return userspace_layout.image_start;
    return userspace_layout.imageBaseForSlot(slot);
}

pub fn stackTopForBundle(bundle_id: []const u8) u64 {
    const slot = imageSlotInGroup(bundle_id) orelse return userspace_layout.default_stack_top;
    return userspace_layout.stackTopForSlot(slot);
}

pub fn protectionKeyForBundle(bundle_id: []const u8) u4 {
    const slot = imageSlotInGroup(bundle_id) orelse return 1;
    return @intCast((slot % 15) + 1);
}

pub fn findByServiceClass(class: contract.ServiceClass) ?*const ImageSpec {
    const spec_index = publicServiceClassSlot(service_class_slots[serviceClassIndex(class)]) orelse return null;
    if (spec_index >= production_boot_image_specs.len) {
        native_util.impossibleByInvariant("boot service class index points outside registry specs");
    }
    return &production_boot_image_specs[spec_index];
}

pub fn contractForSpec(spec: *const ImageSpec) ContractSpec {
    return .{
        .bundle_id = spec.bundleId(),
        .role_tag = spec.roleTag(),
        .heartbeat_increment = spec.heartbeatIncrement(),
        .contract_flags = spec.contractFlags(),
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
        id_index.insert(capacity, &index, bundleIndexKey(spec.bundleId()), spec_index, "boot bundle id index covers userspace registry");
    }
    return index;
}

fn debugAssertBundleIndexMissAbsent(specs: []const ImageSpec, bundle_id: []const u8) void {
    if (@import("builtin").mode != .Debug) return;
    for (specs) |spec| {
        if (std.mem.eql(u8, spec.bundleId(), bundle_id)) {
            native_util.impossibleByInvariant("boot bundle id index missed a registry spec");
        }
    }
}

fn buildServiceClassSlots() ServiceClassSlots {
    var slots = emptyServiceClassSlots();
    inline for (std.meta.fields(contract.ServiceClass)) |field| {
        const class: contract.ServiceClass = @enumFromInt(field.value);
        if (addressSpaceGroupForServiceClass(class)) |group| {
            setServiceClassSlot(&slots, class, @intFromEnum(group));
        }
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
    try std.testing.expect(SINGLE_COMPONENT_BOOT_MANIFESTS_DERIVED_ON_REGISTRATION);
    try std.testing.expect(!@hasField(ImageSpec, "components"));
    try std.testing.expect(RUNTIME_IMAGE_DESCRIPTORS_OMIT_BUILD_LOOKUP_METADATA);
    try std.testing.expect(!@hasField(ImageSpec, "service_class"));
    try std.testing.expect(!@hasField(ImageSpec, "service_kind"));
    try std.testing.expect(COMPACT_RUNTIME_IMAGE_CONTRACT_METADATA);
    try std.testing.expectEqual(RuntimeRoleTag, @FieldType(RuntimeImageMetadata, "role_tag"));
    try std.testing.expectEqual(RuntimeHeartbeatIncrement, @FieldType(RuntimeImageMetadata, "heartbeat_increment"));
    try std.testing.expectEqual(RuntimeContractFlags, @FieldType(RuntimeImageMetadata, "contract_flags"));
    try std.testing.expect(RUNTIME_IMAGE_DESCRIPTORS_USE_COMPACT_PUBLISHERS);
    try std.testing.expectEqual(RuntimePublisher, @FieldType(RuntimeImageMetadata, "publisher"));
    try std.testing.expectEqual(Publisher.system, Publisher.fromName("zigos.system").?);
    try std.testing.expectEqual(Publisher.development, Publisher.fromName("zigos.dev").?);
    try std.testing.expect(Publisher.fromName("zigos.unknown") == null);
    try std.testing.expectEqualStrings("zigos.system", Publisher.system.name());
    try std.testing.expectEqualStrings("zigos.dev", Publisher.development.name());
    try std.testing.expect(RUNTIME_IMAGE_DESCRIPTORS_USE_OPTIONAL_MANIFEST_DECLS);
    try std.testing.expectEqual(?*const [1]manifest.InterfaceDecl, @FieldType(ImageSpec, "provided_interface"));
    try std.testing.expectEqual(?*const [1]manifest.InterfaceDecl, @FieldType(ImageSpec, "consumed_interface"));
    try std.testing.expectEqual(?*const [1]manifest.AssetDecl, @FieldType(ImageSpec, "asset"));
    try std.testing.expect(RUNTIME_IMAGE_DESCRIPTORS_USE_SENTINEL_BOOT_STRINGS);
    try std.testing.expectEqual([*:0]const u8, @FieldType(ImageSpec, "display_name"));
    try std.testing.expectEqual([*:0]const u8, @FieldType(ImageSpec, "label"));
    try std.testing.expectEqual([*:0]const u8, @FieldType(ImageSpec, "entry"));
    try std.testing.expect(RUNTIME_IMAGE_DESCRIPTORS_USE_PACKED_METADATA);
    try std.testing.expectEqual(@as(usize, @sizeOf(u64)), @sizeOf(RuntimeImageMetadata));
    try std.testing.expectEqual([*]const u8, @FieldType(ImageSpec, "bundle_id"));
    try std.testing.expectEqual(RuntimeImageMetadata, @FieldType(ImageSpec, "metadata"));
    try std.testing.expect(@sizeOf(ImageSpec) <= IMAGE_SPEC_SIZE_CEILING_BYTES);
    for (production_build_image_specs, 0..) |build_spec, index| {
        const spec = build_spec.image;
        try std.testing.expect(spec.roleTag() != 0);
        try std.testing.expect(spec.heartbeatIncrement() != 0);
        try std.testing.expectEqual(index, indexForRole(spec.bundleId()).?);
        if (build_spec.service_class) |class| {
            const indexed = findByServiceClass(class) orelse return error.MissingServiceClassIndexEntry;
            try std.testing.expectEqualStrings(spec.bundleId(), indexed.bundleId());
        }

        var peer_index: usize = 0;
        while (peer_index < index) : (peer_index += 1) {
            try std.testing.expect(!std.mem.eql(u8, production_boot_image_specs[peer_index].bundleId(), spec.bundleId()));
            try std.testing.expect(production_boot_image_specs[peer_index].roleTag() != spec.roleTag());
            if (build_spec.service_class) |class| {
                if (production_build_image_specs[peer_index].service_class) |peer_class| {
                    try std.testing.expect(peer_class != class);
                }
            }
        }
    }

    try std.testing.expect(findByServiceClass(.storage_object) != null);
    try std.testing.expect(findByServiceClass(.task_runtime) == null);
}

test "core platform services share six address-space images" {
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.storage_object).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.sync_replication).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.network_stack).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.package_install_update).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.compositor_ui_session).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.attention_broker).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.task_lifecycle).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.sensitive_capture).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.secure_pasteboard).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.object_resilience).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.secret_vault).?.source_path);
    try std.testing.expectEqualStrings("src/userspace/service_main.zig", buildImageByServiceClass(.policy_mediation).?.source_path);
    try std.testing.expectEqualStrings("zigos.system.store", findByServiceClass(.storage_object).?.bundleId());
    try std.testing.expectEqualStrings("zigos.system.drivers", findByServiceClass(.network_stack).?.bundleId());
    try std.testing.expectEqualStrings("zigos.system.session", findByServiceClass(.policy_mediation).?.bundleId());
    try std.testing.expectEqualStrings("zigos.system.privacy", findByServiceClass(.secret_vault).?.bundleId());
}

test "compact runtime manifest declarations preserve populated and empty collections" {
    const notes = findProduction("app.notes") orelse return error.MissingNotesImage;
    try std.testing.expectEqualStrings("app.notes", notes.bundleId());
    try std.testing.expectEqualStrings("Notes", notes.displayName());
    try std.testing.expectEqualStrings("notes", notes.componentLabel());
    try std.testing.expectEqualStrings("app.notes", notes.entryName());
    try std.testing.expectEqual(Publisher.development, notes.publisher());
    try std.testing.expectEqual(manifest.UpdateChannel.beta, notes.updateChannel());
    try std.testing.expectEqual(ComponentClass.app_component, notes.componentClass());
    try std.testing.expectEqual(@as(u32, 0xA107), notes.roleTag());
    try std.testing.expectEqual(@as(u32, 7), notes.heartbeatIncrement());
    try std.testing.expectEqual(@as(u32, FLAG_OWNS_UI_SURFACE), notes.contractFlags());
    try std.testing.expectEqual(@as(usize, 1), notes.providedInterfaces().len);
    try std.testing.expectEqualStrings("zigos.workspace.document", notes.providedInterfaces()[0].name);
    try std.testing.expectEqual(@as(usize, 1), notes.consumedInterfaces().len);
    try std.testing.expectEqualStrings("zigos.object.workspace", notes.consumedInterfaces()[0].name);
    try std.testing.expectEqual(@as(usize, 1), notes.assets().len);
    try std.testing.expectEqualStrings("assets/notes/icon.svg", notes.assets()[0].path);

    const network_service = findByServiceClass(.network_stack) orelse return error.MissingNetworkServiceImage;
    try std.testing.expectEqualStrings("zigos.system.drivers", network_service.bundleId());
    try std.testing.expectEqual(@as(usize, 1), network_service.providedInterfaces().len);
}

test "production userspace registry contains exactly the production boot catalog" {
    try std.testing.expectEqual(@as(usize, 6), production_boot_image_specs.len);
    try std.testing.expectEqual(@as(usize, 6), PRODUCTION_ADDRESS_SPACE_COUNT);
    try std.testing.expect(COLOCATES_SERVICES_BY_ADDRESS_SPACE_GROUP);
    try std.testing.expect(SHARES_GROUP_PAGE_TABLES);
    try std.testing.expect(USES_PKU_WITHIN_GROUP);
    try std.testing.expectEqual(AddressSpaceGroup.store, addressSpaceGroupForServiceClass(.storage_object).?);
    try std.testing.expectEqual(AddressSpaceGroup.session, addressSpaceGroupForServiceClass(.policy_mediation).?);
    try std.testing.expectEqual(AddressSpaceGroup.notes, addressSpaceGroupForBundle("app.notes").?);
    try std.testing.expectEqual(AddressSpaceGroup.drivers, addressSpaceGroupForBundle("zigos.system.drivers").?);
    try std.testing.expectEqualStrings("zigos.system.apps", canonicalProductionBundleId("app.viewer"));
    try std.testing.expectEqualStrings("zigos.system.store", canonicalProductionBundleId("app.sync"));
    try std.testing.expectEqualStrings("zigos.system.privacy", canonicalProductionBundleId("app.capture"));

    var occupied = [_]u16{0} ** PRODUCTION_ADDRESS_SPACE_COUNT;
    for (production_build_image_specs) |spec| {
        const bundle_id = spec.image.bundleId();
        const group = addressSpaceGroupForBundle(bundle_id) orelse return error.MissingAddressSpaceGroup;
        const slot = imageSlotInGroup(bundle_id) orelse return error.MissingImageSlot;
        const bit: u16 = @as(u16, 1) << @as(u4, @intCast(slot));
        const occupied_index = @intFromEnum(group);
        try std.testing.expect(occupied[occupied_index] & bit == 0);
        occupied[occupied_index] |= bit;
        try std.testing.expectEqual(userspace_layout.imageBaseForSlot(slot), imageBaseForBundle(bundle_id));
        try std.testing.expectEqual(userspace_layout.stackTopForSlot(slot), stackTopForBundle(bundle_id));
        try std.testing.expectEqual(@as(u4, @intCast((slot % 15) + 1)), protectionKeyForBundle(bundle_id));
    }

    for (production_boot_image_specs) |spec| {
        const production_spec = findProduction(spec.bundleId()) orelse return error.MissingProductionImage;
        try std.testing.expectEqualStrings(spec.bundleId(), production_spec.bundleId());
        try std.testing.expectEqual(@as(u32, 0), spec.contractFlags() & FLAG_MMU_PROOF_PROBE);
    }
    try std.testing.expect(findProduction("app.notes.daily") == null);
}
