const std = @import("std");
const id_index = @import("../core/id_index.zig");
const capability = @import("../kernel_api/capability.zig");
const component_abi_schema = @import("../services/component_abi_schema.zig");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const units = @import("../core/units.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_mailbox = @import("../task/userspace_bootstrap_mailbox.zig");
const userspace_flags = @import("../task/userspace_flags.zig");

const kibibytes = units.kibibytes;
const mebibytes = units.mebibytes;

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
    attention_broker,
    task_lifecycle,
    permission_review_ui,
    service_registry,
    network_stack,
    storage_object,
    package_install_update,
    compositor_ui_session,
    indexing_search,
    personal_context,
    sync_replication,
    media_print_helpers,
    secure_pasteboard,
    object_resilience,
    sensitive_capture,
    secret_vault,
};

pub const PERMISSION_REVIEW_UI_SURFACE_ID: u64 = 0x100;

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
    source_path: []const u8 = "src/userspace/component_main.zig",
    display_name: []const u8,
    publisher: []const u8 = "zigos.system",
    label: []const u8,
    entry: []const u8,
    role_tag: u32,
    heartbeat_increment: u32,
    contract_flags: u32,
    service_kind: userspace_mailbox.ServiceKind = .generic,
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
    personal_context_service,
    sync_service,
    media_service,
    attention_broker_service,
    task_lifecycle_service,
    pasteboard_service,
    object_resilience_service,
    sensitive_capture_service,
    secret_vault_service,
    task_runtime_service,
};

pub const BootstrapServiceRecordKey = enum(u8) {
    runtime_service_record,
    service_registry,
    policy_service,
    session,
    review_service_record,
    network_service,
    compositor_service,
    storage_service,
    package_service,
    indexing_service,
    personal_context_service,
    sync_service,
    media_service,
    attention_broker_service,
    task_lifecycle_service,
    pasteboard_service,
    object_resilience_service,
    sensitive_capture_service,
    secret_vault_service,
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
    ui_surface_id: ?u64,
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
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE,
        },
        .description = "restartable native session and task coordinator",
        .service_bootstrap = .{
            .mode = .native_direct,
            .budget = .{
                .cpu_time_ticks = 50_000,
                .memory_bytes = mebibytes(8),
                .endpoint_slots = 16,
                .shared_memory_bytes = kibibytes(256),
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
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE | userspace_flags.FLAG_POLICY_BOUNDARY,
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
        .class = .attention_broker,
        .owner_key = .attention_broker_service,
        .service_record_key = .attention_broker_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.attention_broker),
        .required_capabilities = &.{ .service_bootstrap, .policy_authority },
        .dependencies = &.{.policy_mediation},
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true },
        .userspace_image = .{
            .bundle_id = "zigos.system.attention-broker",
            .artifact_name = "userspace-attention-broker.elf",
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Attention Broker",
            .label = "attention-broker",
            .entry = "zigos.attention.broker",
            .role_tag = 0xA11A,
            .heartbeat_increment = 24,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE,
        },
        .description = "policy-gated notification posting, dismissal, query, and attention audit broker",
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.attention_broker),
            .correlation_base = 303,
            .tick = 33,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .task_lifecycle,
        .owner_key = .task_lifecycle_service,
        .service_record_key = .task_lifecycle_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.task_lifecycle),
        .required_capabilities = &.{ .service_bootstrap, .policy_authority },
        .dependencies = &.{ .policy_mediation, .task_runtime },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true },
        .userspace_image = .{
            .bundle_id = "zigos.system.task-lifecycle",
            .artifact_name = "userspace-task-lifecycle.elf",
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Task Lifecycle",
            .label = "task-lifecycle",
            .entry = "zigos.task.lifecycle",
            .role_tag = 0xA11B,
            .heartbeat_increment = 25,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE,
        },
        .description = "policy-gated suspend, resume, terminate, checkpoint-aware lifecycle audit broker",
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.task_lifecycle),
            .correlation_base = 305,
            .tick = 36,
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
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE | userspace_flags.FLAG_OWNS_UI_SURFACE | userspace_flags.FLAG_PERMISSION_REVIEW,
        },
        .description = "task-scoped permission review service for reviewed grants and denials",
        .service_bootstrap = .{
            .mode = .native_direct,
            .budget = .{
                .cpu_time_ticks = 10_000,
                .memory_bytes = kibibytes(512),
                .endpoint_slots = 4,
                .shared_memory_bytes = kibibytes(16),
                .background_allowed = false,
            },
            .correlation_base = 302,
            .tick = 32,
            .ui_surface_id = PERMISSION_REVIEW_UI_SURFACE_ID,
            .grants = &.{.service_task_authority},
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
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE,
        },
        .description = "typed service registration and brokered connection directory",
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = .{
                .cpu_time_ticks = 8_000,
                .memory_bytes = kibibytes(512),
                .endpoint_slots = 8,
                .shared_memory_bytes = kibibytes(64),
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
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Network Stack",
            .label = "network-service",
            .entry = "zigos.service.network.policy",
            .role_tag = 0xA10B,
            .heartbeat_increment = 11,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE | userspace_flags.FLAG_NETWORK_BOUNDARY,
            .service_kind = .network,
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
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Storage Object Service",
            .label = "workspace-storage",
            .entry = "zigos.object.workspace",
            .role_tag = 0xA10C,
            .heartbeat_increment = 12,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE | userspace_flags.FLAG_STORAGE_BOUNDARY,
            .service_kind = .storage,
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
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Package Install Service",
            .label = "package-service",
            .entry = "zigos.package.install",
            .role_tag = 0xA10E,
            .heartbeat_increment = 14,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE,
            .service_kind = .package,
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
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Compositor Session",
            .label = "compositor-session",
            .entry = "zigos.ui.session",
            .role_tag = 0xA10F,
            .heartbeat_increment = 15,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE | userspace_flags.FLAG_OWNS_UI_SURFACE,
            .service_kind = .compositor,
        },
        .description = "compositor, input routing, and UI session ownership",
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.compositor_ui_session),
            .correlation_base = 313,
            .tick = 41,
            .ui_surface_id = 2,
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
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE,
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
        .class = .personal_context,
        .owner_key = .personal_context_service,
        .service_record_key = .personal_context_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.personal_context),
        .required_capabilities = &.{ .service_bootstrap, .metadata_storage },
        .dependencies = &.{ .policy_mediation, .indexing_search },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .storage = .metadata_only },
        .userspace_image = .{
            .bundle_id = "zigos.system.personal-context",
            .artifact_name = "userspace-personal-context.elf",
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Personal Context",
            .label = "personal-context",
            .entry = "zigos.personal.context",
            .role_tag = 0xA11C,
            .heartbeat_increment = 26,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE | userspace_flags.FLAG_STORAGE_BOUNDARY,
        },
        .description = "lease-scoped local semantic memory and agent context retrieval service",
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.personal_context),
            .correlation_base = 337,
            .tick = 65,
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
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Sync Replication",
            .label = "sync-service",
            .entry = "zigos.sync.replication",
            .role_tag = 0xA111,
            .heartbeat_increment = 17,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE | userspace_flags.FLAG_BACKGROUND_ELIGIBLE,
            .service_kind = .sync,
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
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE | userspace_flags.FLAG_BACKGROUND_ELIGIBLE,
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
        .class = .sensitive_capture,
        .owner_key = .sensitive_capture_service,
        .service_record_key = .sensitive_capture_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.sensitive_capture),
        .required_capabilities = &.{ .service_bootstrap, .device_authority, .ui_session_surface },
        .dependencies = &.{ .policy_mediation, .compositor_ui_session },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true },
        .userspace_image = .{
            .bundle_id = "zigos.system.sensitive-capture",
            .artifact_name = "userspace-sensitive-capture.elf",
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Sensitive Capture",
            .label = "sensitive-capture",
            .entry = "zigos.sensitive.capture",
            .role_tag = 0xA118,
            .heartbeat_increment = 22,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE,
        },
        .description = "foreground-only camera, microphone, location, sensor, and screen capture broker",
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.sensitive_capture),
            .correlation_base = 331,
            .tick = 59,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .secure_pasteboard,
        .owner_key = .pasteboard_service,
        .service_record_key = .pasteboard_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.secure_pasteboard),
        .required_capabilities = &.{ .service_bootstrap, .ui_session_surface },
        .dependencies = &.{ .policy_mediation, .compositor_ui_session },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true },
        .userspace_image = .{
            .bundle_id = "zigos.system.secure-pasteboard",
            .artifact_name = "userspace-secure-pasteboard.elf",
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Secure Pasteboard",
            .label = "secure-pasteboard",
            .entry = "zigos.secure.pasteboard",
            .role_tag = 0xA113,
            .heartbeat_increment = 19,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE,
        },
        .description = "destination-bound foreground paste grants without ambient clipboard state",
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.secure_pasteboard),
            .correlation_base = 325,
            .tick = 53,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .object_resilience,
        .owner_key = .object_resilience_service,
        .service_record_key = .object_resilience_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.object_resilience),
        .required_capabilities = &.{ .service_bootstrap, .object_store_authority, .metadata_storage },
        .dependencies = &.{ .policy_mediation, .storage_object },
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true, .storage = .object_store_authority },
        .userspace_image = .{
            .bundle_id = "zigos.system.object-resilience",
            .artifact_name = "userspace-object-resilience.elf",
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Object Resilience",
            .label = "object-resilience",
            .entry = "zigos.object.resilience",
            .role_tag = 0xA117,
            .heartbeat_increment = 21,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE | userspace_flags.FLAG_STORAGE_BOUNDARY,
        },
        .description = "encrypted object backup, restore, and trusted-device migration service",
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.object_resilience),
            .correlation_base = 328,
            .tick = 56,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
    },
    .{
        .class = .secret_vault,
        .owner_key = .secret_vault_service,
        .service_record_key = .secret_vault_service,
        .boundary = .userspace_service,
        .interface = catalogInterface(.secret_vault),
        .required_capabilities = &.{ .service_bootstrap, .policy_authority },
        .dependencies = &.{.policy_mediation},
        .restart_policy = .supervised_restart,
        .isolation = .{ .namespace_isolated = true },
        .userspace_image = .{
            .bundle_id = "zigos.system.secret-vault",
            .artifact_name = "userspace-secret-vault.elf",
            .source_path = "src/userspace/service_main.zig",
            .display_name = "Secret Vault",
            .label = "secret-vault",
            .entry = "zigos.secret.vault",
            .role_tag = 0xA119,
            .heartbeat_increment = 23,
            .contract_flags = userspace_flags.FLAG_SYSTEM_BUNDLE,
        },
        .description = "hardware-sealed secret import, handle lending, rotation, and revocation service",
        .service_bootstrap = .{
            .mode = .kernel_contract,
            .budget = defaultServiceBudget(.secret_vault),
            .correlation_base = 334,
            .tick = 62,
            .grants = &.{.service_task_authority},
        },
        .published_native_service = true,
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
                .ui_surface_id = launch.ui_surface_id,
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

const CATALOG_CLASS_INDEX_CAPACITY: usize = catalog.len * 2;
const catalog_class_index = buildCatalogClassIndex();
const SERVICE_CONTRACT_CLASS_INDEX_CAPACITY: usize = ordered_service_contracts.len * 2;
const service_contract_class_index = buildServiceContractClassIndex();
const PUBLISHED_NATIVE_CLASS_INDEX_CAPACITY: usize = ordered_published_native_service_contracts.len * 2;
const published_native_class_index = buildPublishedNativeClassIndex();

pub const service_catalog_indexing = .{
    .uses_catalog_class_index = @TypeOf(catalog_class_index) == [CATALOG_CLASS_INDEX_CAPACITY]id_index.Slot(CATALOG_CLASS_INDEX_CAPACITY),
    .uses_service_contract_class_index = @TypeOf(service_contract_class_index) == [SERVICE_CONTRACT_CLASS_INDEX_CAPACITY]id_index.Slot(SERVICE_CONTRACT_CLASS_INDEX_CAPACITY),
    .uses_published_contract_class_index = @TypeOf(published_native_class_index) == [PUBLISHED_NATIVE_CLASS_INDEX_CAPACITY]id_index.Slot(PUBLISHED_NATIVE_CLASS_INDEX_CAPACITY),
};

pub fn entryForClass(class: ServiceClass) ?ServiceCatalogEntry {
    const entry_index = catalogClassIndex(class) orelse return null;
    return catalog[entry_index];
}

pub fn serviceDescriptor(class: ServiceClass) ?ServiceDescriptor {
    const entry = entryForClass(class) orelse return null;
    return descriptorFromEntry(entry);
}

pub fn serviceContractForClass(class: ServiceClass) ?ServiceContract {
    const entry_index = orderedServiceIndex(class) orelse return null;
    return ordered_service_contracts[entry_index];
}

pub fn publishedNativeServiceContractForClass(class: ServiceClass) ?PublishedNativeServiceContract {
    const entry_index = orderedPublishedNativeServiceIndex(class) orelse return null;
    return ordered_published_native_service_contracts[entry_index];
}

pub fn orderedServiceIndex(class: ServiceClass) ?usize {
    const entry_index = id_index.lookup(SERVICE_CONTRACT_CLASS_INDEX_CAPACITY, &service_contract_class_index, serviceClassIndexKey(class)) orelse {
        debugAssertServiceContractClassIndexMissAbsent(class);
        return null;
    };
    if (entry_index >= ordered_service_contracts.len) {
        native_util.impossibleByInvariant("service contract class index points outside ordered contracts");
    }
    if (ordered_service_contracts[entry_index].class != class) {
        native_util.impossibleByInvariant("service contract class index points at the wrong contract");
    }
    return entry_index;
}

pub fn orderedPublishedNativeServiceIndex(class: ServiceClass) ?usize {
    const entry_index = id_index.lookup(PUBLISHED_NATIVE_CLASS_INDEX_CAPACITY, &published_native_class_index, serviceClassIndexKey(class)) orelse {
        debugAssertPublishedNativeClassIndexMissAbsent(class);
        return null;
    };
    if (entry_index >= ordered_published_native_service_contracts.len) {
        native_util.impossibleByInvariant("published native service class index points outside ordered contracts");
    }
    if (ordered_published_native_service_contracts[entry_index].class != class) {
        native_util.impossibleByInvariant("published native service class index points at the wrong contract");
    }
    return entry_index;
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
    if (class == .compositor_ui_session and
        (device_class == .usb_controller or
            device_class == .input_device or
            device_class == .compositor_policy))
    {
        return true;
    }
    const entry = entryForClass(class) orelse return false;
    const expected = entry.driver_class orelse return false;
    return expected == device_class;
}

fn serviceClassIndexKey(class: ServiceClass) u64 {
    return @as(u64, @intFromEnum(class)) + 1;
}

fn catalogClassIndex(class: ServiceClass) ?usize {
    const entry_index = id_index.lookup(CATALOG_CLASS_INDEX_CAPACITY, &catalog_class_index, serviceClassIndexKey(class)) orelse {
        debugAssertCatalogClassIndexMissAbsent(class);
        return null;
    };
    if (entry_index >= catalog.len) {
        native_util.impossibleByInvariant("service catalog class index points outside catalog");
    }
    if (catalog[entry_index].class != class) {
        native_util.impossibleByInvariant("service catalog class index points at the wrong entry");
    }
    return entry_index;
}

fn buildCatalogClassIndex() [CATALOG_CLASS_INDEX_CAPACITY]id_index.Slot(CATALOG_CLASS_INDEX_CAPACITY) {
    @setEvalBranchQuota(10_000);
    var index = id_index.emptyTable(CATALOG_CLASS_INDEX_CAPACITY);
    for (catalog, 0..) |entry, entry_index| {
        id_index.insert(CATALOG_CLASS_INDEX_CAPACITY, &index, serviceClassIndexKey(entry.class), entry_index, "service catalog class index covers catalog entries");
    }
    return index;
}

fn buildServiceContractClassIndex() [SERVICE_CONTRACT_CLASS_INDEX_CAPACITY]id_index.Slot(SERVICE_CONTRACT_CLASS_INDEX_CAPACITY) {
    @setEvalBranchQuota(10_000);
    var index = id_index.emptyTable(SERVICE_CONTRACT_CLASS_INDEX_CAPACITY);
    for (ordered_service_contracts, 0..) |entry, entry_index| {
        id_index.insert(SERVICE_CONTRACT_CLASS_INDEX_CAPACITY, &index, serviceClassIndexKey(entry.class), entry_index, "service contract class index covers ordered contracts");
    }
    return index;
}

fn buildPublishedNativeClassIndex() [PUBLISHED_NATIVE_CLASS_INDEX_CAPACITY]id_index.Slot(PUBLISHED_NATIVE_CLASS_INDEX_CAPACITY) {
    @setEvalBranchQuota(10_000);
    var index = id_index.emptyTable(PUBLISHED_NATIVE_CLASS_INDEX_CAPACITY);
    for (ordered_published_native_service_contracts, 0..) |entry, entry_index| {
        id_index.insert(PUBLISHED_NATIVE_CLASS_INDEX_CAPACITY, &index, serviceClassIndexKey(entry.class), entry_index, "published native service class index covers ordered contracts");
    }
    return index;
}

fn debugAssertCatalogClassIndexMissAbsent(class: ServiceClass) void {
    if (@import("builtin").mode != .Debug) return;
    for (catalog) |entry| {
        if (entry.class == class) {
            native_util.impossibleByInvariant("service catalog class index missed an entry");
        }
    }
}

fn debugAssertServiceContractClassIndexMissAbsent(class: ServiceClass) void {
    if (@import("builtin").mode != .Debug) return;
    for (ordered_service_contracts) |entry| {
        if (entry.class == class) {
            native_util.impossibleByInvariant("service contract class index missed an entry");
        }
    }
}

fn debugAssertPublishedNativeClassIndexMissAbsent(class: ServiceClass) void {
    if (@import("builtin").mode != .Debug) return;
    for (ordered_published_native_service_contracts) |entry| {
        if (entry.class == class) {
            native_util.impossibleByInvariant("published native service class index missed an entry");
        }
    }
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
        .attention_broker => "attention_broker",
        .task_lifecycle => "task_lifecycle",
        .permission_review_ui => "permission_review_ui",
        .service_registry => "service_registry",
        .network_stack => "network_stack",
        .storage_object => "storage_object",
        .package_install_update => "package_install_update",
        .compositor_ui_session => "compositor_ui_session",
        .indexing_search => "indexing_search",
        .personal_context => "personal_context",
        .sync_replication => "sync_replication",
        .media_print_helpers => "media_print_helpers",
        .secure_pasteboard => "secure_pasteboard",
        .object_resilience => "object_resilience",
        .sensitive_capture => "sensitive_capture",
        .secret_vault => "secret_vault",
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
            .memory_bytes = mebibytes(1),
            .endpoint_slots = 8,
            .shared_memory_bytes = kibibytes(128),
            .background_allowed = false,
        },
        else => .{
            .cpu_time_ticks = 8_000,
            .memory_bytes = kibibytes(512),
            .endpoint_slots = 6,
            .shared_memory_bytes = kibibytes(64),
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
    try std.testing.expectEqual(@as(usize, 16), ordered_service_contracts.len);
    try std.testing.expectEqual(@as(usize, 15), ordered_published_native_service_contracts.len);
    try std.testing.expectEqual(component_abi_schema.service_catalog_bindings.len, catalog.len);
    try std.testing.expectEqual(ServiceClass.service_registry, ordered_service_contracts[0].class);
    try std.testing.expectEqual(ServiceClass.policy_mediation, ordered_service_contracts[1].class);
    try std.testing.expectEqual(ServiceClass.attention_broker, ordered_service_contracts[2].class);
    try std.testing.expectEqual(ServiceClass.task_lifecycle, ordered_service_contracts[3].class);
    try std.testing.expectEqual(ServiceClass.personal_context, ordered_service_contracts[9].class);
    try std.testing.expectEqual(ServiceClass.sensitive_capture, ordered_service_contracts[12].class);
    try std.testing.expectEqual(ServiceClass.secure_pasteboard, ordered_service_contracts[13].class);
    try std.testing.expectEqual(ServiceClass.object_resilience, ordered_service_contracts[14].class);
    try std.testing.expectEqual(ServiceClass.secret_vault, ordered_service_contracts[15].class);
    try std.testing.expectEqual(ServiceClass.attention_broker, ordered_published_native_service_contracts[1].class);
    try std.testing.expectEqual(ServiceClass.task_lifecycle, ordered_published_native_service_contracts[2].class);
    try std.testing.expectEqual(ServiceClass.personal_context, ordered_published_native_service_contracts[8].class);
    try std.testing.expectEqual(ServiceClass.sensitive_capture, ordered_published_native_service_contracts[11].class);
    try std.testing.expectEqual(ServiceClass.secure_pasteboard, ordered_published_native_service_contracts[12].class);
    try std.testing.expectEqual(ServiceClass.object_resilience, ordered_published_native_service_contracts[13].class);
    try std.testing.expectEqual(ServiceClass.secret_vault, ordered_published_native_service_contracts[14].class);
    try std.testing.expectEqualStrings(component_abi_schema.interfaceForService(.storage_object).name, entryForClass(.storage_object).?.interface.name);
    try std.testing.expectEqualStrings("zigos.system.storage-object", bundleIdForServiceClass(.storage_object).?);
    try std.testing.expectEqual(@as(usize, 0), orderedServiceIndex(.service_registry).?);
    try std.testing.expectEqual(@as(usize, 1), orderedServiceIndex(.policy_mediation).?);
    try std.testing.expectEqual(@as(usize, 1), orderedPublishedNativeServiceIndex(.attention_broker).?);
    try std.testing.expectEqual(@as(?usize, null), orderedServiceIndex(.task_runtime));
    try std.testing.expectEqual(@as(?usize, null), orderedPublishedNativeServiceIndex(.session_manager));
    try std.testing.expect(allowsDriverClass(.network_stack, .network_adapter));
    try std.testing.expect(allowsDriverClass(.compositor_ui_session, .usb_controller));
    try std.testing.expect(allowsDriverClass(.compositor_ui_session, .graphics_adapter));
    try std.testing.expect(allowsDriverClass(.compositor_ui_session, .input_device));
    try std.testing.expect(allowsDriverClass(.compositor_ui_session, .compositor_policy));
    try std.testing.expect(allowsDriverClass(.media_print_helpers, .audio_print_io));
    try std.testing.expect(!allowsDriverClass(.policy_mediation, .network_adapter));
    try std.testing.expect(!allowsDriverClass(.policy_mediation, .compositor_policy));
    try std.testing.expectEqual(BootstrapLaunchMode.native_direct, bootstrapLaunchForClass(.session_manager).?.mode);
    try std.testing.expectEqual(BootstrapOwnerKey.storage_service, bootstrapOwnerKeyForClass(.storage_object).?);
    try std.testing.expectEqual(BootstrapServiceRecordKey.storage_service, bootstrapServiceRecordKeyForClass(.storage_object).?);
    try std.testing.expectEqual(component_abi_schema.InterfaceId.object_workspace, serviceContractForClass(.storage_object).?.interface_id);
}

test "service catalog interfaces remain unique and dependencies point at catalog entries" {
    for (catalog, 0..) |entry, index| {
        try std.testing.expectEqual(entry.class, entryForClass(entry.class).?.class);
        try std.testing.expect(entry.required_capabilities.len != 0);
        for (entry.dependencies) |dependency| {
            try std.testing.expect(entryForClass(dependency) != null);
        }

        var peer_index: usize = index + 1;
        while (peer_index < catalog.len) : (peer_index += 1) {
            try std.testing.expect(entry.class != catalog[peer_index].class);
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
            if (entry.isolation.ui == .session_surface) {
                try std.testing.expect(launch.ui_surface_id != null);
                try std.testing.expect(launch.ui_surface_id.? != 0);
            }
        }
    }
}
