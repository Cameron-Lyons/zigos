const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const principal = @import("../core/principal.zig");
const capability = @import("../kernel_api/capability.zig");
const service_catalog = @import("service_catalog.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service = @import("../task/task_runtime_service.zig");
const userspace_boot_registry = @import("../task/userspace_boot_registry.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

pub const Principals = struct {
    policy_authority: principal.PrincipalId,
    session_service: principal.PrincipalId,
    session_user: principal.PrincipalId,
    network_service: principal.PrincipalId,
    compositor_service: principal.PrincipalId,
    storage_service: principal.PrincipalId,
    review_service: principal.PrincipalId,
    package_service: principal.PrincipalId,
    indexing_service: principal.PrincipalId,
    personal_context_service: principal.PrincipalId,
    sync_service: principal.PrincipalId,
    media_service: principal.PrincipalId,
    attention_broker_service: principal.PrincipalId,
    task_lifecycle_service: principal.PrincipalId,
    pasteboard_service: principal.PrincipalId,
    object_resilience_service: principal.PrincipalId,
    sensitive_capture_service: principal.PrincipalId,
    secret_vault_service: principal.PrincipalId,
    task_runtime_service: principal.PrincipalId,
};

pub const CoreServices = std.EnumArray(service_catalog.ServiceClass, *supervisor_mod.ServiceRecord);

/// Supervisor service ids follow this order, so it also fixes the measured policy digest.
const registration_order = [_]service_catalog.ServiceClass{
    .task_runtime,
    .service_registry,
    .policy_mediation,
    .session_manager,
    .permission_review_ui,
    .network_stack,
    .compositor_ui_session,
    .storage_object,
    .package_install_update,
    .indexing_search,
    .personal_context,
    .sync_replication,
    .media_print_helpers,
    .attention_broker,
    .task_lifecycle,
    .secure_pasteboard,
    .object_resilience,
    .sensitive_capture,
    .secret_vault,
};

comptime {
    if (registration_order.len != service_catalog.SERVICE_CLASS_COUNT) {
        @compileError("every service class registers exactly one core service record");
    }
    for (registration_order, 0..) |class, index| {
        for (registration_order[0..index]) |earlier| {
            if (earlier == class) @compileError("duplicate core service registration");
        }
    }
}

pub const Error = userspace_boot_registry.Error || supervisor_mod.Error;

pub fn principals() Principals {
    return .{
        .policy_authority = .{ .kind = .policy_authority, .serial = 1 },
        .session_service = .{ .kind = .service, .serial = 1 },
        .session_user = .{ .kind = .user, .serial = 1 },
        .network_service = .{ .kind = .service, .serial = 2 },
        .compositor_service = .{ .kind = .service, .serial = 3 },
        .storage_service = .{ .kind = .service, .serial = 4 },
        .review_service = .{ .kind = .service, .serial = 5 },
        .package_service = .{ .kind = .service, .serial = 6 },
        .indexing_service = .{ .kind = .service, .serial = 7 },
        .personal_context_service = .{ .kind = .service, .serial = 17 },
        .sync_service = .{ .kind = .service, .serial = 8 },
        .media_service = .{ .kind = .service, .serial = 9 },
        .attention_broker_service = .{ .kind = .service, .serial = 15 },
        .task_lifecycle_service = .{ .kind = .service, .serial = 16 },
        .pasteboard_service = .{ .kind = .service, .serial = 11 },
        .object_resilience_service = .{ .kind = .service, .serial = 12 },
        .sensitive_capture_service = .{ .kind = .service, .serial = 13 },
        .secret_vault_service = .{ .kind = .service, .serial = 14 },
        .task_runtime_service = .{ .kind = .service, .serial = 10 },
    };
}

pub fn initializeUserspace(
    catalog: *userspace_loader.Catalog,
    runtime: *task_runtime.Runtime,
    capability_table: *const capability.CapabilityTable,
    scheduler: *userspace_scheduler.Scheduler,
) userspace_boot_registry.Error!void {
    catalog.reset();
    try userspace_boot_registry.registerAll(catalog);
    scheduler.bind(catalog, runtime, capability_table);
    if (catalog.imageCount() != 0) {
        common.printBootMarker(boot_markers.userspace_artifacts_ready);
        common.printBootMarker(boot_markers.userspace_scheduler_ready);
    }
}

pub fn registerCoreServices(
    supervisor: *supervisor_mod.Supervisor,
    runtime_service: *task_runtime_service.Service,
    ids: Principals,
) supervisor_mod.Error!CoreServices {
    var services: CoreServices = undefined;
    for (registration_order) |class| {
        services.set(class, try supervisor.register(class, ownerForServiceClass(ids, class)));
    }

    runtime_service.bind(services.get(.task_runtime).id, ids.task_runtime_service);

    for (service_catalog.catalog) |entry| {
        _ = supervisor.markHealthy(services.get(entry.class).id);
    }

    common.printBootMarker(boot_markers.supervisor_ready);
    if (service_catalog.serviceDescriptor(.policy_mediation).?.boundary == .userspace_service and
        service_catalog.serviceDescriptor(.network_stack).?.boundary == .userspace_service and
        service_catalog.serviceDescriptor(.storage_object).?.boundary == .userspace_service)
    {
        common.printBootMarker(boot_markers.service_contract_map_ready);
    }

    return services;
}

pub fn ownerForServiceClass(ids: Principals, class: service_catalog.ServiceClass) principal.PrincipalId {
    return switch (class) {
        .task_runtime => ids.task_runtime_service,
        .session_manager => ids.session_service,
        .policy_mediation, .service_registry => ids.policy_authority,
        .attention_broker => ids.attention_broker_service,
        .task_lifecycle => ids.task_lifecycle_service,
        .permission_review_ui => ids.review_service,
        .network_stack => ids.network_service,
        .storage_object => ids.storage_service,
        .package_install_update => ids.package_service,
        .compositor_ui_session => ids.compositor_service,
        .indexing_search => ids.indexing_service,
        .personal_context => ids.personal_context_service,
        .sync_replication => ids.sync_service,
        .media_print_helpers => ids.media_service,
        .secure_pasteboard => ids.pasteboard_service,
        .object_resilience => ids.object_resilience_service,
        .sensitive_capture => ids.sensitive_capture_service,
        .secret_vault => ids.secret_vault_service,
    };
}

test "bootstrap service ownership and service records resolve from service catalog wiring" {
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.init(&runtime);
    var supervisor = supervisor_mod.Supervisor.init();
    const ids = principals();
    const services = try registerCoreServices(&supervisor, &runtime_service, ids);

    try std.testing.expectEqual(ids.storage_service, ownerForServiceClass(ids, .storage_object));
    for (registration_order, 1..) |class, expected_id| {
        const service = services.get(class);
        try std.testing.expectEqual(@as(u64, expected_id), service.id);
        try std.testing.expectEqual(ownerForServiceClass(ids, class), service.owner);
        try std.testing.expectEqual(service, supervisor.findByClass(class).?);
    }
}
