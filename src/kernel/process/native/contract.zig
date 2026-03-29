const std = @import("std");
const driver_service = @import("driver_service.zig");

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

pub const IsolationProfile = struct {
    namespace_isolated: bool,
    zero_ambient_authority: bool = true,
    network: NetworkPrivilege = .none,
    storage: StoragePrivilege = .none,
    ui: UiPrivilege = .none,
    driver_class: ?driver_service.DeviceClass = null,
};

pub const ServiceDescriptor = struct {
    class: ServiceClass,
    boundary: ServiceBoundary,
    restartable: bool,
    isolation: IsolationProfile,
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

pub const default_services = [_]ServiceDescriptor{
    .{
        .class = .task_runtime,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
        },
        .description = "restartable task ownership, UI state, resource budgeting, and audit context service",
    },
    .{
        .class = .session_manager,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .ui = .session_surface,
        },
        .description = "restartable native session and task coordinator",
    },
    .{
        .class = .policy_mediation,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
        },
        .description = "grant, deny, and audit mediation for object, network, and device access",
    },
    .{
        .class = .permission_review_ui,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .ui = .review_surface,
        },
        .description = "task-scoped permission review service for reviewed grants and denials",
    },
    .{
        .class = .service_registry,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
        },
        .description = "typed service registration and brokered connection directory",
    },
    .{
        .class = .compatibility_portal,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .network = .named_peer_brokered,
            .ui = .review_surface,
        },
        .description = "isolated VM, container, emulation, and remote-session compatibility portal service",
    },
    .{
        .class = .network_stack,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .network = .unrestricted_brokered,
            .driver_class = .network_adapter,
        },
        .description = "restartable network and policy service running behind capability IPC",
    },
    .{
        .class = .storage_object,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .storage = .object_store_authority,
            .driver_class = .storage_controller,
        },
        .description = "restartable object-store authority surface replacing direct kernel storage ownership",
    },
    .{
        .class = .package_install_update,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .storage = .metadata_only,
            .network = .named_peer_brokered,
        },
        .description = "bundle install and update service",
    },
    .{
        .class = .compositor_ui_session,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .ui = .session_surface,
            .driver_class = .graphics_adapter,
        },
        .description = "native compositor and UI session service",
    },
    .{
        .class = .indexing_search,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .storage = .metadata_only,
        },
        .description = "indexing and search service",
    },
    .{
        .class = .sync_replication,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .network = .named_peer_brokered,
            .storage = .metadata_only,
        },
        .description = "local-first replication, device graph, and relay-assisted sync",
    },
    .{
        .class = .media_print_helpers,
        .boundary = .userspace_service,
        .restartable = true,
        .isolation = .{
            .namespace_isolated = true,
            .driver_class = .audio_print_io,
        },
        .description = "media and print helper services",
    },
};

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

pub fn serviceDescriptor(class: ServiceClass) ?ServiceDescriptor {
    for (default_services) |descriptor| {
        if (descriptor.class == class) return descriptor;
    }
    return null;
}

pub fn allowsDriverClass(class: ServiceClass, device_class: driver_service.DeviceClass) bool {
    const descriptor = serviceDescriptor(class) orelse return false;
    const expected = descriptor.isolation.driver_class orelse return false;
    return expected == device_class;
}

test "kernel tcb contains the expected bootstrap surface" {
    try std.testing.expectEqual(@as(usize, 7), kernel_tcb.len);
    try std.testing.expectEqualStrings("ipc_transport", tcbName(.ipc_transport));
    try std.testing.expectEqualStrings("iommu_dma_isolation_hooks", tcbName(.iommu_dma_isolation_hooks));
}

test "native bootstrap and phase3 services sit behind restartable userspace contracts" {
    const runtime = serviceDescriptor(.task_runtime).?;
    const session = serviceDescriptor(.session_manager).?;
    const registry = serviceDescriptor(.service_registry).?;
    const compatibility_service = serviceDescriptor(.compatibility_portal).?;
    const network = serviceDescriptor(.network_stack).?;
    const storage = serviceDescriptor(.storage_object).?;
    const policy = serviceDescriptor(.policy_mediation).?;

    try std.testing.expectEqual(ServiceBoundary.userspace_service, runtime.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, session.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, registry.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, compatibility_service.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, network.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, storage.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, policy.boundary);
    try std.testing.expect(runtime.restartable);
    try std.testing.expect(compatibility_service.restartable);
    try std.testing.expect(runtime.isolation.namespace_isolated);
    try std.testing.expectEqual(NetworkPrivilege.unrestricted_brokered, network.isolation.network);
    try std.testing.expectEqual(StoragePrivilege.object_store_authority, storage.isolation.storage);
    try std.testing.expectEqual(UiPrivilege.review_surface, compatibility_service.isolation.ui);
    try std.testing.expect(allowsDriverClass(.network_stack, .network_adapter));
    try std.testing.expect(allowsDriverClass(.storage_object, .storage_controller));
    try std.testing.expect(!allowsDriverClass(.policy_mediation, .network_adapter));
}
