const builtin = @import("builtin");
const boot_markers = @import("../../boot/markers.zig");
const common = if (builtin.target.os.tag == .freestanding)
    @import("../../boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const contract = @import("contract.zig");
const principal = @import("principal.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("task_runtime.zig");
const task_runtime_service = @import("task_runtime_service.zig");
const userspace_boot_registry = @import("userspace_boot_registry.zig");
const userspace_loader = @import("userspace_loader.zig");
const userspace_scheduler = @import("userspace_scheduler.zig");

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
    sync_service: principal.PrincipalId,
    media_service: principal.PrincipalId,
    task_runtime_service: principal.PrincipalId,
    compatibility_service: principal.PrincipalId,
};

pub const CoreServices = struct {
    runtime_service_record: *supervisor_mod.ServiceRecord,
    service_registry: *supervisor_mod.ServiceRecord,
    policy_service: *supervisor_mod.ServiceRecord,
    session: *supervisor_mod.ServiceRecord,
    review_service_record: *supervisor_mod.ServiceRecord,
    compatibility_service: *supervisor_mod.ServiceRecord,
    network_service: *supervisor_mod.ServiceRecord,
    compositor_service: *supervisor_mod.ServiceRecord,
    storage_service: *supervisor_mod.ServiceRecord,
    package_service: *supervisor_mod.ServiceRecord,
    indexing_service: *supervisor_mod.ServiceRecord,
    sync_service: *supervisor_mod.ServiceRecord,
    media_service: *supervisor_mod.ServiceRecord,
};

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
        .sync_service = .{ .kind = .service, .serial = 8 },
        .media_service = .{ .kind = .service, .serial = 9 },
        .task_runtime_service = .{ .kind = .service, .serial = 10 },
        .compatibility_service = .{ .kind = .service, .serial = 11 },
    };
}

pub fn initializeUserspace(catalog: *userspace_loader.Catalog, runtime: *task_runtime.Runtime) void {
    catalog.* = userspace_loader.Catalog.init();
    userspace_boot_registry.registerAll(catalog) catch unreachable;
    userspace_scheduler.init(catalog, runtime);
    if (catalog.imageCount() != 0) {
        common.printBootMarker(boot_markers.userspace_artifacts_ready);
    }
}

pub fn registerCoreServices(
    supervisor: *supervisor_mod.Supervisor,
    runtime_service: *task_runtime_service.Service,
    ids: Principals,
) CoreServices {
    const services = CoreServices{
        .runtime_service_record = supervisor.register(.task_runtime, ids.task_runtime_service) catch unreachable,
        .service_registry = supervisor.register(.service_registry, ids.policy_authority) catch unreachable,
        .policy_service = supervisor.register(.policy_mediation, ids.policy_authority) catch unreachable,
        .session = supervisor.register(.session_manager, ids.session_service) catch unreachable,
        .review_service_record = supervisor.register(.permission_review_ui, ids.review_service) catch unreachable,
        .compatibility_service = supervisor.register(.compatibility_portal, ids.compatibility_service) catch unreachable,
        .network_service = supervisor.register(.network_stack, ids.network_service) catch unreachable,
        .compositor_service = supervisor.register(.compositor_ui_session, ids.compositor_service) catch unreachable,
        .storage_service = supervisor.register(.storage_object, ids.storage_service) catch unreachable,
        .package_service = supervisor.register(.package_install_update, ids.package_service) catch unreachable,
        .indexing_service = supervisor.register(.indexing_search, ids.indexing_service) catch unreachable,
        .sync_service = supervisor.register(.sync_replication, ids.sync_service) catch unreachable,
        .media_service = supervisor.register(.media_print_helpers, ids.media_service) catch unreachable,
    };

    runtime_service.bind(services.runtime_service_record.id, ids.task_runtime_service);

    _ = supervisor.markHealthy(services.runtime_service_record.id, 0);
    _ = supervisor.markHealthy(services.service_registry.id, 0);
    _ = supervisor.markHealthy(services.policy_service.id, 0);
    _ = supervisor.markHealthy(services.session.id, 0);
    _ = supervisor.markHealthy(services.review_service_record.id, 0);
    _ = supervisor.markHealthy(services.compatibility_service.id, 0);
    _ = supervisor.markHealthy(services.network_service.id, 0);
    _ = supervisor.markHealthy(services.compositor_service.id, 0);
    _ = supervisor.markHealthy(services.storage_service.id, 0);
    _ = supervisor.markHealthy(services.package_service.id, 0);
    _ = supervisor.markHealthy(services.indexing_service.id, 0);
    _ = supervisor.markHealthy(services.sync_service.id, 0);
    _ = supervisor.markHealthy(services.media_service.id, 0);

    common.printBootMarker(boot_markers.supervisor_ready);
    if (contract.serviceDescriptor(.policy_mediation).?.boundary == .userspace_service and
        contract.serviceDescriptor(.network_stack).?.boundary == .userspace_service and
        contract.serviceDescriptor(.storage_object).?.boundary == .userspace_service)
    {
        common.printBootMarker(boot_markers.phase3_contract_map_ready);
    }

    return services;
}
