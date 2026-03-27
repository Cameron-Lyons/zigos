const std = @import("std");

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

pub const ServiceDescriptor = struct {
    class: ServiceClass,
    boundary: ServiceBoundary,
    restartable: bool,
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
        .boundary = .in_process_bridge,
        .restartable = false,
        .description = "task ownership, UI state, resource budgeting, and audit context",
    },
    .{
        .class = .session_manager,
        .boundary = .in_process_bridge,
        .restartable = true,
        .description = "bootstrap task/session manager until the native UI stack moves behind IPC",
    },
    .{
        .class = .policy_mediation,
        .boundary = .userspace_service,
        .restartable = true,
        .description = "grant, deny, and audit mediation for object, network, and device access",
    },
    .{
        .class = .permission_review_ui,
        .boundary = .userspace_service,
        .restartable = true,
        .description = "task-scoped permission review service for reviewed grants and denials",
    },
    .{
        .class = .service_registry,
        .boundary = .in_process_bridge,
        .restartable = true,
        .description = "typed service registration and brokered connection directory",
    },
    .{
        .class = .network_stack,
        .boundary = .userspace_service,
        .restartable = true,
        .description = "restartable network and policy service running behind capability IPC",
    },
    .{
        .class = .storage_object,
        .boundary = .userspace_service,
        .restartable = true,
        .description = "restartable object-store authority surface replacing direct kernel storage ownership",
    },
    .{
        .class = .package_install_update,
        .boundary = .userspace_service,
        .restartable = true,
        .description = "bundle install and update service",
    },
    .{
        .class = .compositor_ui_session,
        .boundary = .userspace_service,
        .restartable = true,
        .description = "native compositor and UI session service",
    },
    .{
        .class = .indexing_search,
        .boundary = .userspace_service,
        .restartable = true,
        .description = "indexing and search service",
    },
    .{
        .class = .sync_replication,
        .boundary = .userspace_service,
        .restartable = true,
        .description = "local-first replication, device graph, and relay-assisted sync",
    },
    .{
        .class = .media_print_helpers,
        .boundary = .userspace_service,
        .restartable = true,
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

test "kernel tcb contains the expected bootstrap surface" {
    try std.testing.expectEqual(@as(usize, 7), kernel_tcb.len);
    try std.testing.expectEqualStrings("ipc_transport", tcbName(.ipc_transport));
    try std.testing.expectEqualStrings("iommu_dma_isolation_hooks", tcbName(.iommu_dma_isolation_hooks));
}

test "phase3 moves native network and storage behind restartable userspace contracts" {
    const network = serviceDescriptor(.network_stack).?;
    const storage = serviceDescriptor(.storage_object).?;
    const policy = serviceDescriptor(.policy_mediation).?;

    try std.testing.expectEqual(ServiceBoundary.userspace_service, network.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, storage.boundary);
    try std.testing.expectEqual(ServiceBoundary.userspace_service, policy.boundary);
}
