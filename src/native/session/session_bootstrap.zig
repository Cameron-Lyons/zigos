const builtin = @import("builtin");
const native_util = @import("../core/util.zig");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const contract = @import("contract.zig");
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

pub const CoreServices = struct {
    runtime_service_record: *supervisor_mod.ServiceRecord,
    service_registry: *supervisor_mod.ServiceRecord,
    policy_service: *supervisor_mod.ServiceRecord,
    session: *supervisor_mod.ServiceRecord,
    review_service_record: *supervisor_mod.ServiceRecord,
    network_service: *supervisor_mod.ServiceRecord,
    compositor_service: *supervisor_mod.ServiceRecord,
    storage_service: *supervisor_mod.ServiceRecord,
    package_service: *supervisor_mod.ServiceRecord,
    indexing_service: *supervisor_mod.ServiceRecord,
    personal_context_service: *supervisor_mod.ServiceRecord,
    sync_service: *supervisor_mod.ServiceRecord,
    media_service: *supervisor_mod.ServiceRecord,
    attention_broker_service: *supervisor_mod.ServiceRecord,
    task_lifecycle_service: *supervisor_mod.ServiceRecord,
    pasteboard_service: *supervisor_mod.ServiceRecord,
    object_resilience_service: *supervisor_mod.ServiceRecord,
    sensitive_capture_service: *supervisor_mod.ServiceRecord,
    secret_vault_service: *supervisor_mod.ServiceRecord,
};

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
    const services = CoreServices{
        .runtime_service_record = try supervisor.register(.task_runtime, ids.task_runtime_service),
        .service_registry = try supervisor.register(.service_registry, ids.policy_authority),
        .policy_service = try supervisor.register(.policy_mediation, ids.policy_authority),
        .session = try supervisor.register(.session_manager, ids.session_service),
        .review_service_record = try supervisor.register(.permission_review_ui, ids.review_service),
        .network_service = try supervisor.register(.network_stack, ids.network_service),
        .compositor_service = try supervisor.register(.compositor_ui_session, ids.compositor_service),
        .storage_service = try supervisor.register(.storage_object, ids.storage_service),
        .package_service = try supervisor.register(.package_install_update, ids.package_service),
        .indexing_service = try supervisor.register(.indexing_search, ids.indexing_service),
        .personal_context_service = try supervisor.register(.personal_context, ids.personal_context_service),
        .sync_service = try supervisor.register(.sync_replication, ids.sync_service),
        .media_service = try supervisor.register(.media_print_helpers, ids.media_service),
        .attention_broker_service = try supervisor.register(.attention_broker, ids.attention_broker_service),
        .task_lifecycle_service = try supervisor.register(.task_lifecycle, ids.task_lifecycle_service),
        .pasteboard_service = try supervisor.register(.secure_pasteboard, ids.pasteboard_service),
        .object_resilience_service = try supervisor.register(.object_resilience, ids.object_resilience_service),
        .sensitive_capture_service = try supervisor.register(.sensitive_capture, ids.sensitive_capture_service),
        .secret_vault_service = try supervisor.register(.secret_vault, ids.secret_vault_service),
    };

    runtime_service.bind(services.runtime_service_record.id, ids.task_runtime_service);

    for (service_catalog.catalog) |entry| {
        const service = serviceRecordForClass(services, entry.class) orelse
            native_util.impossibleByInvariant("the service catalog registers a record for every class");
        _ = supervisor.markHealthy(service.id);
    }

    common.printBootMarker(boot_markers.supervisor_ready);
    if (contract.serviceDescriptor(.policy_mediation).?.boundary == .userspace_service and
        contract.serviceDescriptor(.network_stack).?.boundary == .userspace_service and
        contract.serviceDescriptor(.storage_object).?.boundary == .userspace_service)
    {
        common.printBootMarker(boot_markers.service_contract_map_ready);
    }

    return services;
}

pub fn ownerForServiceClass(ids: Principals, class: contract.ServiceClass) ?principal.PrincipalId {
    const owner_key = service_catalog.bootstrapOwnerKeyForClass(class) orelse return null;
    return principalForOwnerKey(ids, owner_key);
}

pub fn serviceRecordForClass(services: CoreServices, class: contract.ServiceClass) ?*supervisor_mod.ServiceRecord {
    const record_key = service_catalog.bootstrapServiceRecordKeyForClass(class) orelse return null;
    return serviceRecordForKey(services, record_key);
}

pub fn serviceIdForClass(services: CoreServices, class: contract.ServiceClass) ?u64 {
    const service = serviceRecordForClass(services, class) orelse return null;
    return service.id;
}

fn principalForOwnerKey(ids: Principals, owner_key: service_catalog.BootstrapOwnerKey) principal.PrincipalId {
    return switch (owner_key) {
        .policy_authority => ids.policy_authority,
        .session_service => ids.session_service,
        .network_service => ids.network_service,
        .compositor_service => ids.compositor_service,
        .storage_service => ids.storage_service,
        .review_service => ids.review_service,
        .package_service => ids.package_service,
        .indexing_service => ids.indexing_service,
        .personal_context_service => ids.personal_context_service,
        .sync_service => ids.sync_service,
        .media_service => ids.media_service,
        .attention_broker_service => ids.attention_broker_service,
        .task_lifecycle_service => ids.task_lifecycle_service,
        .pasteboard_service => ids.pasteboard_service,
        .object_resilience_service => ids.object_resilience_service,
        .sensitive_capture_service => ids.sensitive_capture_service,
        .secret_vault_service => ids.secret_vault_service,
        .task_runtime_service => ids.task_runtime_service,
    };
}

fn serviceRecordForKey(services: CoreServices, record_key: service_catalog.BootstrapServiceRecordKey) *supervisor_mod.ServiceRecord {
    return switch (record_key) {
        .runtime_service_record => services.runtime_service_record,
        .service_registry => services.service_registry,
        .policy_service => services.policy_service,
        .session => services.session,
        .review_service_record => services.review_service_record,
        .network_service => services.network_service,
        .compositor_service => services.compositor_service,
        .storage_service => services.storage_service,
        .package_service => services.package_service,
        .indexing_service => services.indexing_service,
        .personal_context_service => services.personal_context_service,
        .sync_service => services.sync_service,
        .media_service => services.media_service,
        .attention_broker_service => services.attention_broker_service,
        .task_lifecycle_service => services.task_lifecycle_service,
        .pasteboard_service => services.pasteboard_service,
        .object_resilience_service => services.object_resilience_service,
        .sensitive_capture_service => services.sensitive_capture_service,
        .secret_vault_service => services.secret_vault_service,
    };
}

test "bootstrap service ownership and service records resolve from service catalog wiring" {
    var runtime = task_runtime.Runtime.init();
    var runtime_service = task_runtime_service.Service.init(&runtime);
    var supervisor = supervisor_mod.Supervisor.init();
    const ids = principals();
    const services = try registerCoreServices(&supervisor, &runtime_service, ids);

    try std.testing.expectEqual(ids.storage_service, ownerForServiceClass(ids, .storage_object).?);
    try std.testing.expectEqual(services.storage_service.id, serviceIdForClass(services, .storage_object).?);
    for (service_catalog.catalog) |entry| {
        const owner = ownerForServiceClass(ids, entry.class) orelse return error.TestUnexpectedResult;
        const service = serviceRecordForClass(services, entry.class) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(owner, service.owner);
    }
}
