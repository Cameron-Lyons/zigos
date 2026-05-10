const std = @import("std");
const fixed_table = @import("../core/fixed_table.zig");
const capability = @import("../kernel_api/capability.zig");
const component_abi_schema = @import("../services/component_abi_schema.zig");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");
const task_runtime = @import("../task/task_runtime.zig");

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

pub const BootstrapLaunchMode = enum(u8) {
    native_direct,
    kernel_contract,
};

pub const BootstrapGrantKind = enum(u8) {
    session_service_authority,
    policy_mint_authority,
    service_task_authority,
};

pub const BootstrapOwnerKey = enum(u8) {
    policy_authority,
    session_service,
    network_service,
    compositor_service,
    storage_service,
    review_service,
    package_service,
    indexing_service,
    sync_service,
    media_service,
    task_runtime_service,
    compatibility_service,
};

pub const BootstrapServiceRecordKey = enum(u8) {
    runtime_service_record,
    service_registry,
    policy_service,
    session,
    review_service_record,
    compatibility_service,
    network_service,
    compositor_service,
    storage_service,
    package_service,
    indexing_service,
    sync_service,
    media_service,
};

pub const BootstrapLaunch = struct {
    mode: BootstrapLaunchMode,
    budget: task_runtime.ResourceBudget,
    correlation_base: u64,
    tick: u64,
    ui_surface_id: ?u64 = null,
    grants: []const BootstrapGrantKind = &.{},
};

pub const ServiceCatalogEntry = struct {
    class: ServiceClass,
    owner_key: BootstrapOwnerKey,
    service_record_key: BootstrapServiceRecordKey,
    boundary: ServiceBoundary,
    interface: manifest.InterfaceDecl,
    required_capabilities: []const RequiredCapability = &.{},
    dependencies: []const ServiceClass = &.{},
    driver_class: ?driver_service.DeviceClass = null,
    restart_policy: RestartPolicy,
    isolation: IsolationProfile,
    userspace_image: ?UserspaceImageIdentity = null,
    description: []const u8,
    service_bootstrap: ?BootstrapLaunch = null,
    published_native_service: bool = false,

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
    interface_id: component_abi_schema.InterfaceId,
    interface: manifest.InterfaceDecl,
    driver_class: ?driver_service.DeviceClass = null,
    description: []const u8,
    boot_budget: task_runtime.ResourceBudget,
    boot_correlation_base: u64,
    boot_tick: u64,
    bootstrap_grants: []const BootstrapGrantKind,
};

pub const PublishedNativeServiceContract = struct {
    class: ServiceClass,
    interface_id: component_abi_schema.InterfaceId,
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

fn catalogInterface(comptime class: ServiceClass) manifest.InterfaceDecl {
    inline for (@typeInfo(component_abi_schema.ServiceBinding).@"enum".fields) |field| {
        if (std.mem.eql(u8, field.name, @tagName(class))) {
            return component_abi_schema.interfaceForService(@enumFromInt(field.value));
        }
    }
    @compileError("service catalog class is missing a component ABI service binding");
}

pub const catalog = [_]ServiceCatalogEntry{
    .{
        .class = .task_runtime,
        .owner_key = .task_runtime_service,
        .service_record_key = .runtime_service_record,
        .boundary = .userspace_service,
        .interface = catalogInterface(.task_runtime),
        .required_capabilities = &.{.service_bootstrap},
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true },
        .description = "restartable task ownership, UI state, resource budgeting, and audit context service",
    },
    .{
        .class = .session_manager,
        .owner_key = .session_service,
        .service_record_key = .session,
        .boundary = .userspace_service,
        .interface = catalogInterface(.session_manager),
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
        .service_bootstrap = .{
            .mode = .native_direct,
            .budget = .{
                .cpu_time_ticks = 50_000,
                .memory_bytes = 8 * 1024 * 1024,
                .endpoint_slots = 16,
                .shared_memory_bytes = 256 * 1024,
                .background_allowed = false,
            },
            .correlation_base = 0,
            .tick = 0,
            .ui_surface_id = 1,
            .grants = &.{ .session_service_authority, .policy_mint_authority },
        },
    },
    .{
        .class = .policy_mediation,
        .owner_key = .policy_authority,
        .service_record_key = .policy_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.policy_mediation),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.policy_mediation),
            .correlation_base = 301,
            .tick = 31,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .permission_review_ui,
        .owner_key = .review_service,
        .service_record_key = .review_service_record,
        .boundary = .userspace_service,
        .interface = catalogInterface(.permission_review_ui),
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
        .service_bootstrap = .{
            .mode = .native_direct,
            .budget = .{
                .cpu_time_ticks = 10_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 16 * 1024,
                .background_allowed = false,
            },
            .correlation_base = 302,
            .tick = 32,
        },
    },
    .{
        .class = .service_registry,
        .owner_key = .policy_authority,
        .service_record_key = .service_registry,
        .boundary = .userspace_service,
        .interface = catalogInterface(.service_registry),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = .{
                .cpu_time_ticks = 8_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 8,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .correlation_base = 24,
            .tick = 24,
            .grants = &.{.service_task_authority},
        },
    },
    .{
        .class = .network_stack,
        .owner_key = .network_service,
        .service_record_key = .network_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.network_stack),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.network_stack),
            .correlation_base = 304,
            .tick = 34,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .storage_object,
        .owner_key = .storage_service,
        .service_record_key = .storage_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.storage_object),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.storage_object),
            .correlation_base = 307,
            .tick = 35,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .package_install_update,
        .owner_key = .package_service,
        .service_record_key = .package_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.package_install_update),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.package_install_update),
            .correlation_base = 310,
            .tick = 38,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .compositor_ui_session,
        .owner_key = .compositor_service,
        .service_record_key = .compositor_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.compositor_ui_session),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.compositor_ui_session),
            .correlation_base = 313,
            .tick = 41,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .indexing_search,
        .owner_key = .indexing_service,
        .service_record_key = .indexing_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.indexing_search),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.indexing_search),
            .correlation_base = 316,
            .tick = 44,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .sync_replication,
        .owner_key = .sync_service,
        .service_record_key = .sync_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.sync_replication),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.sync_replication),
            .correlation_base = 319,
            .tick = 47,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .media_print_helpers,
        .owner_key = .media_service,
        .service_record_key = .media_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.media_print_helpers),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.media_print_helpers),
            .correlation_base = 322,
            .tick = 50,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .compatibility_portal,
        .owner_key = .compatibility_service,
        .service_record_key = .compatibility_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.compatibility_portal),
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
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.compatibility_portal),
            .correlation_base = 325,
            .tick = 51,
            .grants = &.{.service_task_authority},
        },
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
    const count = kernelBootstrapCount();
    var derived: [count]ServiceContract = undefined;
    var used = [_]bool{false} ** catalog.len;
    var count_out: usize = 0;
    while (count_out < count) {
        var progressed = false;
        for (catalog, 0..) |entry, index| {
            const launch = entry.service_bootstrap orelse continue;
            if (launch.mode != .kernel_contract or used[index]) continue;
            if (!dependenciesSatisfied(entry, derived[0..count_out])) continue;

            derived[count_out] = .{
                .class = entry.class,
                .interface_id = component_abi_schema.interfaceIdForService(@field(component_abi_schema.ServiceBinding, @tagName(entry.class))),
                .interface = entry.interface,
                .driver_class = entry.driver_class,
                .description = entry.description,
                .boot_budget = launch.budget,
                .boot_correlation_base = launch.correlation_base,
                .boot_tick = launch.tick,
                .bootstrap_grants = launch.grants,
            };
            used[index] = true;
            count_out += 1;
            progressed = true;
            break;
        }
        if (!progressed) @compileError("service catalog bootstrap dependencies contain a cycle or missing precondition");
    }
    break :blk derived;
};

pub const ordered_published_native_service_contracts = blk: {
    const count = publishedNativeServiceCount();
    var derived: [count]PublishedNativeServiceContract = undefined;
    var index: usize = 0;
    for (catalog) |entry| {
        if (entry.published_native_service) {
            derived[index] = .{
                .class = entry.class,
                .interface_id = component_abi_schema.interfaceIdForService(@field(component_abi_schema.ServiceBinding, @tagName(entry.class))),
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
    const entry = fixed_table.findValue(ServiceCatalogEntry, catalog[0..], class, catalogEntryMatchesClass) orelse return null;
    return entry.*;
}

pub fn serviceDescriptor(class: ServiceClass) ?ServiceDescriptor {
    const entry = entryForClass(class) orelse return null;
    return descriptorFromEntry(entry);
}

pub fn serviceContractForClass(class: ServiceClass) ?ServiceContract {
    const entry = fixed_table.findValue(ServiceContract, ordered_service_contracts[0..], class, serviceContractMatchesClass) orelse return null;
    return entry.*;
}

pub fn publishedNativeServiceContractForClass(class: ServiceClass) ?PublishedNativeServiceContract {
    const entry = fixed_table.findValue(PublishedNativeServiceContract, ordered_published_native_service_contracts[0..], class, publishedNativeContractMatchesClass) orelse return null;
    return entry.*;
}

pub fn orderedServiceIndex(class: ServiceClass) ?usize {
    return fixed_table.findValueIndex(ServiceContract, ordered_service_contracts[0..], class, serviceContractMatchesClass);
}

pub fn orderedPublishedNativeServiceIndex(class: ServiceClass) ?usize {
    return fixed_table.findValueIndex(PublishedNativeServiceContract, ordered_published_native_service_contracts[0..], class, publishedNativeContractMatchesClass);
}

pub fn imageForClass(class: ServiceClass) ?UserspaceImageIdentity {
    const entry = entryForClass(class) orelse return null;
    return entry.userspace_image;
}

pub fn bundleIdForServiceClass(class: ServiceClass) ?[]const u8 {
    const image = imageForClass(class) orelse return null;
    return image.bundle_id;
}

pub fn bootstrapLaunchForClass(class: ServiceClass) ?BootstrapLaunch {
    const entry = entryForClass(class) orelse return null;
    return entry.service_bootstrap;
}

pub fn bootstrapOwnerKeyForClass(class: ServiceClass) ?BootstrapOwnerKey {
    const entry = entryForClass(class) orelse return null;
    return entry.owner_key;
}

pub fn bootstrapServiceRecordKeyForClass(class: ServiceClass) ?BootstrapServiceRecordKey {
    const entry = entryForClass(class) orelse return null;
    return entry.service_record_key;
}

pub fn rightsForBootstrapGrant(kind: BootstrapGrantKind) capability.CapabilityRights {
    return switch (kind) {
        .session_service_authority => .{ .service = .{
            .task_create = true,
            .endpoint_create = true,
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_derive = true,
            .capability_query = true,
            .shared_memory_create = true,
            .shared_memory_map = true,
            .shared_memory_unmap = true,
            .shared_memory_revoke = true,
            .time_query = true,
            .resource_query = true,
            .accounting_query = true,
            .ipc_peer = true,
        } },
        .policy_mint_authority => .{ .policy = .{
            .capability_mint = true,
            .capability_query = true,
            .capability_revoke = true,
        } },
        .service_task_authority => .{ .service = .{
            .endpoint_create = true,
            .endpoint_connect = true,
            .ipc_peer = true,
        } },
    };
}

pub fn allowsDriverClass(class: ServiceClass, device_class: driver_service.DeviceClass) bool {
    if (class == .compositor_ui_session and device_class == .input_device) return true;
    const entry = entryForClass(class) orelse return false;
    const expected = entry.driver_class orelse return false;
    return expected == device_class;
}

fn catalogEntryMatchesClass(class: ServiceClass, entry: *const ServiceCatalogEntry) bool {
    return entry.class == class;
}

fn serviceContractMatchesClass(class: ServiceClass, entry: *const ServiceContract) bool {
    return entry.class == class;
}

fn publishedNativeContractMatchesClass(class: ServiceClass, entry: *const PublishedNativeServiceContract) bool {
    return entry.class == class;
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

fn kernelBootstrapCount() usize {
    comptime var count: usize = 0;
    inline for (catalog) |entry| {
        if (entry.service_bootstrap) |launch| {
            if (launch.mode == .kernel_contract) count += 1;
        }
    }
    return count;
}

fn isKernelBootstrapClass(class: ServiceClass) bool {
    const entry = entryForClass(class) orelse return false;
    const launch = entry.service_bootstrap orelse return false;
    return launch.mode == .kernel_contract;
}

fn dependenciesSatisfied(entry: ServiceCatalogEntry, ordered: []const ServiceContract) bool {
    for (entry.dependencies) |dependency| {
        if (!isKernelBootstrapClass(dependency)) continue;
        var found = false;
        for (ordered) |contract_entry| {
            if (contract_entry.class == dependency) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn defaultServiceBudget(class: ServiceClass) task_runtime.ResourceBudget {
    return switch (class) {
        .network_stack, .storage_object, .compositor_ui_session => .{
            .cpu_time_ticks = 16_000,
            .memory_bytes = 1024 * 1024,
            .endpoint_slots = 8,
            .shared_memory_bytes = 128 * 1024,
            .background_allowed = false,
        },
        else => .{
            .cpu_time_ticks = 8_000,
            .memory_bytes = 512 * 1024,
            .endpoint_slots = 6,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = false,
        },
    };
}

fn publishedNativeServiceCount() usize {
    comptime var count: usize = 0;
    inline for (catalog) |entry| {
        if (entry.published_native_service) count += 1;
    }
    return count;
}

test "service catalog derives descriptors and bootstrap contracts from one source" {
    try std.testing.expectEqual(@as(usize, catalog.len), default_services.len);
    try std.testing.expectEqual(@as(usize, 10), ordered_service_contracts.len);
    try std.testing.expectEqual(@as(usize, 8), ordered_published_native_service_contracts.len);
    try std.testing.expectEqual(component_abi_schema.service_catalog_bindings.len, catalog.len);
    try std.testing.expectEqual(ServiceClass.service_registry, ordered_service_contracts[0].class);
    try std.testing.expectEqual(ServiceClass.policy_mediation, ordered_service_contracts[1].class);
    try std.testing.expectEqual(ServiceClass.compatibility_portal, ordered_service_contracts[9].class);
    try std.testing.expectEqual(ServiceClass.media_print_helpers, ordered_published_native_service_contracts[7].class);
    try std.testing.expectEqualStrings(component_abi_schema.interfaceForService(.storage_object).name, entryForClass(.storage_object).?.interface.name);
    try std.testing.expectEqualStrings("zigos.system.storage-object", bundleIdForServiceClass(.storage_object).?);
    try std.testing.expect(allowsDriverClass(.network_stack, .network_adapter));
    try std.testing.expect(allowsDriverClass(.compositor_ui_session, .graphics_adapter));
    try std.testing.expect(allowsDriverClass(.compositor_ui_session, .input_device));
    try std.testing.expect(allowsDriverClass(.media_print_helpers, .audio_print_io));
    try std.testing.expect(!allowsDriverClass(.policy_mediation, .network_adapter));
    try std.testing.expectEqual(BootstrapLaunchMode.native_direct, bootstrapLaunchForClass(.session_manager).?.mode);
    try std.testing.expectEqual(BootstrapOwnerKey.storage_service, bootstrapOwnerKeyForClass(.storage_object).?);
    try std.testing.expectEqual(BootstrapServiceRecordKey.storage_service, bootstrapServiceRecordKeyForClass(.storage_object).?);
    try std.testing.expectEqual(component_abi_schema.InterfaceId.object_workspace, serviceContractForClass(.storage_object).?.interface_id);
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

test "default service catalog keeps native services userspace restartable and zero ambient" {
    for (catalog) |entry| {
        try std.testing.expectEqual(ServiceBoundary.userspace_service, entry.boundary);
        try std.testing.expectEqual(RestartPolicy.supervised_restart, entry.restart_policy);
        try std.testing.expect(entry.isolation.namespace_isolated);
        try std.testing.expect(entry.isolation.zero_ambient_authority);

        if (entry.driver_class) |driver_class| {
            try std.testing.expect(entry.isolation.driver_class != null);
            try std.testing.expectEqual(driver_class, entry.isolation.driver_class.?);
            try std.testing.expect(allowsDriverClass(entry.class, driver_class));
        }

        if (entry.service_bootstrap) |launch| {
            if (launch.mode == .kernel_contract) {
                try std.testing.expect(entry.userspace_image != null);
                try std.testing.expect(launch.grants.len != 0);
                try std.testing.expectEqual(BootstrapGrantKind.service_task_authority, launch.grants[0]);
            }
        }
    }
}
