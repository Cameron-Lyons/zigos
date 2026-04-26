const std = @import("std");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");

pub const KernelTcbComponent = enum(u8) {
    scheduling,
    virtual_memory,
    ipc_transport,
    capability_table_enforcement,
    interrupts_timekeeping,
    secure_boot_handoff_hooks,
    iommu_dma_isolation_hooks,
};

pub const ServiceClass = enum(u8) {
    task_runtime,
    session_manager,
    policy_mediation,
    permission_review_ui,
    service_registry,
    compatibility_portal,
    network_stack,
    storage_object,
    package_install_update,
    compositor_ui_session,
    indexing_search,
    sync_replication,
    media_print_helpers,
};

pub const ServiceBoundary = enum(u8) {
    kernel_tcb,
    in_process_bridge,
    userspace_service,
};

pub const NetworkPrivilege = enum(u8) {
    none,
    local_brokered,
    named_peer_brokered,
    unrestricted_brokered,
};

pub const StoragePrivilege = enum(u8) {
    none,
    metadata_only,
    object_store_authority,
};

pub const UiPrivilege = enum(u8) {
    none,
    review_surface,
    session_surface,
};

pub const RequiredCapability = enum(u8) {
    service_bootstrap,
    policy_authority,
    permission_review,
    endpoint_registry,
    named_peer_network,
    unrestricted_network,
    object_store_authority,
    metadata_storage,
    ui_review_surface,
    ui_session_surface,
    background_execution,
    device_authority,
};

pub const RestartPolicy = enum(u8) {
    never,
    supervised_restart,
};

pub const IsolationProfile = struct {
    namespace_isolated: bool,
    zero_ambient_authority: bool = true,
    network: NetworkPrivilege = .none,
    storage: StoragePrivilege = .none,
    ui: UiPrivilege = .none,
    driver_class: ?driver_service.DeviceClass = null,
};

pub const UserspaceImageIdentity = struct {
    bundle_id: []const u8,
    artifact_name: []const u8,
    display_name: []const u8,
    publisher: []const u8 = "zigos.system",
    label: []const u8,
    entry: []const u8,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32,
};

pub const BootstrapTiming = struct {
    correlation_base: u64,
    tick: u64,
};

pub const ServiceCatalogEntry = struct {
    class: ServiceClass,
    boundary: ServiceBoundary,
    interface: manifest.InterfaceDecl,
    required_capabilities: []const RequiredCapability = &.{},
    dependencies: []const ServiceClass = &.{},
    driver_class: ?driver_service.DeviceClass = null,
    restart_policy: RestartPolicy,
    isolation: IsolationProfile,
    userspace_image: ?UserspaceImageIdentity = null,
    description: []const u8,
    service_bootstrap: ?BootstrapTiming = null,
    legacy_phase3: bool = false,

    pub fn restartable(self: ServiceCatalogEntry) bool {
        return self.restart_policy == .supervised_restart;
    }
};

pub const ServiceDescriptor = struct {
    class: ServiceClass,
    boundary: ServiceBoundary,
    restartable: bool,
    isolation: IsolationProfile,
    description: []const u8,
};

pub const ServiceContract = struct {
    class: ServiceClass,
    interface: manifest.InterfaceDecl,
    driver_class: ?driver_service.DeviceClass = null,
    description: []const u8,
    boot_correlation_base: u64,
    boot_tick: u64,
};

pub const Phase3Contract = struct {
    class: ServiceClass,
    interface: manifest.InterfaceDecl,
    driver_class: ?driver_service.DeviceClass = null,
    description: []const u8,
};

pub const kernel_tcb = [_]KernelTcbComponent{
    .scheduling,
    .virtual_memory,
    .ipc_transport,
    .capability_table_enforcement,
    .interrupts_timekeeping,
    .secure_boot_handoff_hooks,
    .iommu_dma_isolation_hooks,
};

pub const catalog = [_]ServiceCatalogEntry{
    .{
        .class = .task_runtime,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.task.runtime" },
        .required_capabilities = &.{.service_bootstrap},
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true },
        .description = "restartable task ownership, UI state, resource budgeting, and audit context service",
    },
    .{
        .class = .session_manager,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.session.manager" },
        .required_capabilities = &.{ .service_bootstrap, .ui_session_surface },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .ui = .session_surface },
        .userspace_image = .{
            .bundle_id = "zigos.system.session-manager",
            .artifact_name = "userspace-session-manager.elf",
            .display_name = "Session Manager",
            .label = "session-manager",
            .entry = "zigos.session.manager",
            .role_tag = 0xA101,
            .heartbeat_increment = 1,
            .contract_flags = 1 << 0,
        },
        .description = "restartable native session and task coordinator",
    },
    .{
        .class = .policy_mediation,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.policy.mediation" },
        .required_capabilities = &.{ .service_bootstrap, .policy_authority },
        .dependencies = &.{.service_registry},
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true },
        .userspace_image = .{
            .bundle_id = "zigos.system.policy-mediation",
            .artifact_name = "userspace-policy-mediation.elf",
            .display_name = "Policy Mediation",
            .label = "policy-mediation",
            .entry = "zigos.policy.mediation",
            .role_tag = 0xA10A,
            .heartbeat_increment = 10,
            .contract_flags = (1 << 0) | (1 << 6),
        },
        .description = "runtime grants, denials, and policy enforcement",
        .service_bootstrap = .{ .correlation_base = 301, .tick = 31 },
        .legacy_phase3 = true,
    },
    .{
        .class = .permission_review_ui,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.permission.review" },
        .required_capabilities = &.{ .service_bootstrap, .permission_review, .ui_review_surface },
        .dependencies = &.{.policy_mediation},
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .ui = .review_surface },
        .userspace_image = .{
            .bundle_id = "zigos.system.permission-review",
            .artifact_name = "userspace-permission-review.elf",
            .display_name = "Permission Review",
            .label = "permission-review",
            .entry = "zigos.permission.review",
            .role_tag = 0xA102,
            .heartbeat_increment = 2,
            .contract_flags = (1 << 0) | (1 << 1) | (1 << 2),
        },
        .description = "task-scoped permission review service for reviewed grants and denials",
    },
    .{
        .class = .service_registry,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.service.registry" },
        .required_capabilities = &.{ .service_bootstrap, .endpoint_registry },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true },
        .userspace_image = .{
            .bundle_id = "zigos.system.service-registry",
            .artifact_name = "userspace-service-registry.elf",
            .display_name = "Service Registry",
            .label = "service-registry",
            .entry = "zigos.service.registry",
            .role_tag = 0xA115,
            .heartbeat_increment = 21,
            .contract_flags = 1 << 0,
        },
        .description = "typed service registration and brokered connection directory",
    },
    .{
        .class = .network_stack,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.service.network.policy" },
        .required_capabilities = &.{ .service_bootstrap, .unrestricted_network, .device_authority },
        .dependencies = &.{.policy_mediation},
        .driver_class = .network_adapter,
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .network = .unrestricted_brokered, .driver_class = .network_adapter },
        .userspace_image = .{
            .bundle_id = "zigos.system.network-stack",
            .artifact_name = "userspace-network-stack.elf",
            .display_name = "Network Stack",
            .label = "network-service",
            .entry = "zigos.service.network.policy",
            .role_tag = 0xA10B,
            .heartbeat_increment = 11,
            .contract_flags = (1 << 0) | (1 << 5),
        },
        .description = "network stack, egress mediation, and device-backed packet IO",
        .service_bootstrap = .{ .correlation_base = 304, .tick = 34 },
        .legacy_phase3 = true,
    },
    .{
        .class = .storage_object,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.object.workspace" },
        .required_capabilities = &.{ .service_bootstrap, .object_store_authority, .device_authority },
        .dependencies = &.{.policy_mediation},
        .driver_class = .storage_controller,
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .storage = .object_store_authority, .driver_class = .storage_controller },
        .userspace_image = .{
            .bundle_id = "zigos.system.storage-object",
            .artifact_name = "userspace-storage-object.elf",
            .display_name = "Storage Object Service",
            .label = "workspace-storage",
            .entry = "zigos.object.workspace",
            .role_tag = 0xA10C,
            .heartbeat_increment = 12,
            .contract_flags = (1 << 0) | (1 << 4),
        },
        .description = "content-addressed object versions, workspace authority, snapshots, and derived file-bridge views",
        .service_bootstrap = .{ .correlation_base = 307, .tick = 35 },
        .legacy_phase3 = true,
    },
    .{
        .class = .package_install_update,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.package.install" },
        .required_capabilities = &.{ .service_bootstrap, .metadata_storage, .named_peer_network },
        .dependencies = &.{ .policy_mediation, .storage_object, .network_stack },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .storage = .metadata_only, .network = .named_peer_brokered },
        .userspace_image = .{
            .bundle_id = "zigos.system.package-service",
            .artifact_name = "userspace-package-service.elf",
            .display_name = "Package Install Service",
            .label = "package-service",
            .entry = "zigos.package.install",
            .role_tag = 0xA10E,
            .heartbeat_increment = 14,
            .contract_flags = 1 << 0,
        },
        .description = "bundle install, update, and channel management",
        .service_bootstrap = .{ .correlation_base = 310, .tick = 38 },
        .legacy_phase3 = true,
    },
    .{
        .class = .compositor_ui_session,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.ui.session" },
        .required_capabilities = &.{ .service_bootstrap, .ui_session_surface, .device_authority },
        .dependencies = &.{.policy_mediation},
        .driver_class = .graphics_adapter,
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .ui = .session_surface, .driver_class = .graphics_adapter },
        .userspace_image = .{
            .bundle_id = "zigos.system.compositor",
            .artifact_name = "userspace-compositor.elf",
            .display_name = "Compositor Session",
            .label = "compositor-session",
            .entry = "zigos.ui.session",
            .role_tag = 0xA10F,
            .heartbeat_increment = 15,
            .contract_flags = (1 << 0) | (1 << 1),
        },
        .description = "compositor, input routing, and UI session ownership",
        .service_bootstrap = .{ .correlation_base = 313, .tick = 41 },
        .legacy_phase3 = true,
    },
    .{
        .class = .indexing_search,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.index.search" },
        .required_capabilities = &.{ .service_bootstrap, .metadata_storage },
        .dependencies = &.{.storage_object},
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .storage = .metadata_only },
        .userspace_image = .{
            .bundle_id = "zigos.system.indexing-search",
            .artifact_name = "userspace-indexing-search.elf",
            .display_name = "Indexing Search",
            .label = "indexing-service",
            .entry = "zigos.index.search",
            .role_tag = 0xA110,
            .heartbeat_increment = 16,
            .contract_flags = 1 << 0,
        },
        .description = "indexing and search query service",
        .service_bootstrap = .{ .correlation_base = 316, .tick = 44 },
        .legacy_phase3 = true,
    },
    .{
        .class = .sync_replication,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.sync.replication" },
        .required_capabilities = &.{ .service_bootstrap, .named_peer_network, .metadata_storage, .background_execution },
        .dependencies = &.{ .storage_object, .network_stack },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .network = .named_peer_brokered, .storage = .metadata_only },
        .userspace_image = .{
            .bundle_id = "zigos.system.sync-service",
            .artifact_name = "userspace-sync-service.elf",
            .display_name = "Sync Replication",
            .label = "sync-service",
            .entry = "zigos.sync.replication",
            .role_tag = 0xA111,
            .heartbeat_increment = 17,
            .contract_flags = (1 << 0) | (1 << 3),
        },
        .description = "local-first sync and replication service",
        .service_bootstrap = .{ .correlation_base = 319, .tick = 47 },
        .legacy_phase3 = true,
    },
    .{
        .class = .media_print_helpers,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.media.print" },
        .required_capabilities = &.{ .service_bootstrap, .device_authority, .background_execution },
        .dependencies = &.{.policy_mediation},
        .driver_class = .audio_print_io,
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .driver_class = .audio_print_io },
        .userspace_image = .{
            .bundle_id = "zigos.system.media-print",
            .artifact_name = "userspace-media-print.elf",
            .display_name = "Media Print Helpers",
            .label = "media-print-service",
            .entry = "zigos.media.print",
            .role_tag = 0xA112,
            .heartbeat_increment = 18,
            .contract_flags = (1 << 0) | (1 << 3),
        },
        .description = "media and print helper pipeline",
        .service_bootstrap = .{ .correlation_base = 322, .tick = 50 },
        .legacy_phase3 = true,
    },
    .{
        .class = .compatibility_portal,
        .boundary = .userspace_service,
        .interface = .{ .name = "zigos.compat.portal" },
        .required_capabilities = &.{ .service_bootstrap, .named_peer_network, .ui_review_surface },
        .dependencies = &.{ .policy_mediation, .network_stack, .compositor_ui_session },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .network = .named_peer_brokered, .ui = .review_surface },
        .userspace_image = .{
            .bundle_id = "zigos.system.compatibility-portal",
            .artifact_name = "userspace-compatibility-portal.elf",
            .display_name = "Compatibility Portal",
            .label = "compatibility-portal",
            .entry = "zigos.compat.portal",
            .role_tag = 0xA113,
            .heartbeat_increment = 19,
            .contract_flags = (1 << 0) | (1 << 8),
        },
        .description = "isolated compatibility portal service",
        .service_bootstrap = .{ .correlation_base = 325, .tick = 51 },
    },
};

pub const default_services = blk: {
    var derived: [catalog.len]ServiceDescriptor = undefined;
    for (catalog, 0..) |entry, index| {
        derived[index] = descriptorFromEntry(entry);
    }
    break :blk derived;
};

pub const ordered_service_contracts = blk: {
    const count = serviceBootstrapCount();
    var derived: [count]ServiceContract = undefined;
    var index: usize = 0;
    for (catalog) |entry| {
        if (entry.service_bootstrap) |timing| {
            derived[index] = .{
                .class = entry.class,
                .interface = entry.interface,
                .driver_class = entry.driver_class,
                .description = entry.description,
                .boot_correlation_base = timing.correlation_base,
                .boot_tick = timing.tick,
            };
            index += 1;
        }
    }
    break :blk derived;
};

pub const ordered_phase3_contracts = blk: {
    const count = legacyPhase3Count();
    var derived: [count]Phase3Contract = undefined;
    var index: usize = 0;
    for (catalog) |entry| {
        if (entry.legacy_phase3) {
            derived[index] = .{
                .class = entry.class,
                .interface = entry.interface,
                .driver_class = entry.driver_class,
                .description = entry.description,
            };
            index += 1;
        }
    }
    break :blk derived;
};

pub fn entryForClass(class: ServiceClass) ?ServiceCatalogEntry {
    for (catalog) |entry| {
        if (entry.class == class) return entry;
    }
    return null;
}

pub fn serviceDescriptor(class: ServiceClass) ?ServiceDescriptor {
    const entry = entryForClass(class) orelse return null;
    return descriptorFromEntry(entry);
}

pub fn serviceContractForClass(class: ServiceClass) ?ServiceContract {
    for (ordered_service_contracts) |entry| {
        if (entry.class == class) return entry;
    }
    return null;
}

pub fn phase3ContractForClass(class: ServiceClass) ?Phase3Contract {
    for (ordered_phase3_contracts) |entry| {
        if (entry.class == class) return entry;
    }
    return null;
}

pub fn orderedServiceIndex(class: ServiceClass) ?usize {
    for (ordered_service_contracts, 0..) |entry, index| {
        if (entry.class == class) return index;
    }
    return null;
}

pub fn orderedPhase3Index(class: ServiceClass) ?usize {
    for (ordered_phase3_contracts, 0..) |entry, index| {
        if (entry.class == class) return index;
    }
    return null;
}

pub fn imageForClass(class: ServiceClass) ?UserspaceImageIdentity {
    const entry = entryForClass(class) orelse return null;
    return entry.userspace_image;
}

pub fn bundleIdForServiceClass(class: ServiceClass) ?[]const u8 {
    const image = imageForClass(class) orelse return null;
    return image.bundle_id;
}

pub fn allowsDriverClass(class: ServiceClass, device_class: driver_service.DeviceClass) bool {
    const entry = entryForClass(class) orelse return false;
    const expected = entry.driver_class orelse return false;
    return expected == device_class;
}

pub fn tcbName(component: KernelTcbComponent) []const u8 {
    return switch (component) {
        .scheduling => "scheduling",
        .virtual_memory => "virtual_memory",
        .ipc_transport => "ipc_transport",
        .capability_table_enforcement => "capability_table_enforcement",
        .interrupts_timekeeping => "interrupts_timekeeping",
        .secure_boot_handoff_hooks => "secure_boot_handoff_hooks",
        .iommu_dma_isolation_hooks => "iommu_dma_isolation_hooks",
    };
}

pub fn serviceName(class: ServiceClass) []const u8 {
    return switch (class) {
        .task_runtime => "task_runtime",
        .session_manager => "session_manager",
        .policy_mediation => "policy_mediation",
        .permission_review_ui => "permission_review_ui",
        .service_registry => "service_registry",
        .compatibility_portal => "compatibility_portal",
        .network_stack => "network_stack",
        .storage_object => "storage_object",
        .package_install_update => "package_install_update",
        .compositor_ui_session => "compositor_ui_session",
        .indexing_search => "indexing_search",
        .sync_replication => "sync_replication",
        .media_print_helpers => "media_print_helpers",
    };
}

fn descriptorFromEntry(entry: ServiceCatalogEntry) ServiceDescriptor {
    return .{
        .class = entry.class,
        .boundary = entry.boundary,
        .restartable = entry.restartable(),
        .isolation = entry.isolation,
        .description = entry.description,
    };
}

fn serviceBootstrapCount() usize {
    comptime var count: usize = 0;
    inline for (catalog) |entry| {
        if (entry.service_bootstrap != null) count += 1;
    }
    return count;
}

fn legacyPhase3Count() usize {
    comptime var count: usize = 0;
    inline for (catalog) |entry| {
        if (entry.legacy_phase3) count += 1;
    }
    return count;
}

test "service catalog derives descriptors and bootstrap contracts from one source" {
    try std.testing.expectEqual(@as(usize, catalog.len), default_services.len);
    try std.testing.expectEqual(@as(usize, 9), ordered_service_contracts.len);
    try std.testing.expectEqual(@as(usize, 8), ordered_phase3_contracts.len);
    try std.testing.expectEqual(ServiceClass.policy_mediation, ordered_service_contracts[0].class);
    try std.testing.expectEqual(ServiceClass.compatibility_portal, ordered_service_contracts[8].class);
    try std.testing.expectEqual(ServiceClass.media_print_helpers, ordered_phase3_contracts[7].class);
    try std.testing.expectEqualStrings("zigos.system.storage-object", bundleIdForServiceClass(.storage_object).?);
    try std.testing.expect(allowsDriverClass(.network_stack, .network_adapter));
    try std.testing.expect(!allowsDriverClass(.policy_mediation, .network_adapter));
}

test "service catalog interfaces remain unique and dependencies point at catalog entries" {
    for (catalog, 0..) |entry, index| {
        try std.testing.expect(entry.required_capabilities.len != 0);
        for (entry.dependencies) |dependency| {
            try std.testing.expect(entryForClass(dependency) != null);
        }

        var peer_index: usize = index + 1;
        while (peer_index < catalog.len) : (peer_index += 1) {
            try std.testing.expect(!std.mem.eql(u8, entry.interface.name, catalog[peer_index].interface.name));
        }
    }
}
