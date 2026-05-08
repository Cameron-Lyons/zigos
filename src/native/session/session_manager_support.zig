const capability = @import("../kernel_api/capability.zig");
const component_abi_schema = @import("../services/component_abi_schema.zig");
const contract = @import("contract.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const manifest = @import("../policy/manifest.zig");
const native_service_registry = @import("../services/service_registry.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const service_bootstrap = @import("service_bootstrap.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const package_service = @import("../services/package_service.zig");
const principal = @import("../core/principal.zig");
const session_bootstrap = @import("session_bootstrap.zig");
const service_contract = @import("service_contracts.zig");
const supervisor_mod = @import("supervisor.zig");
const background_dispatch = @import("../task/background_dispatch.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

pub const bootstrap_storage_interface = component_abi_schema.interfaceDecl(.bootstrap_workspace);
pub const compatibility_portal_interface = component_abi_schema.interfaceForService(.compatibility_portal);

pub const BootstrapState = struct {
    ids: session_bootstrap.Principals,
    services: session_bootstrap.CoreServices,
    session_task: *task_runtime.TaskRecord,
    review_service_task: *task_runtime.TaskRecord,
    session_capability: capability.Capability,
    policy_capability: capability.Capability,
};

pub const NotesReviewState = struct {
    task_id: u64,
    network_permission: manifest.PermissionRequest,
    grants_len: usize,
    grants: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant,
    object_capability: capability.Capability,

    pub fn grantsSlice(self: *const NotesReviewState) []const policy_mediation.UserGrant {
        return self.grants[0..self.grants_len];
    }
};

pub const ServiceBindings = struct {
    bindings: [service_contract.ordered_service_contracts.len]service_bootstrap.ServiceBinding,

    pub fn init() ServiceBindings {
        return .{
            .bindings = [_]service_bootstrap.ServiceBinding{.{ .task_id = 0, .endpoint_id = 0 }} ** service_contract.ordered_service_contracts.len,
        };
    }

    pub fn bindingFor(self: *const ServiceBindings, class: contract.ServiceClass) service_bootstrap.ServiceBinding {
        return self.bindings[service_contract.orderedIndex(class).?];
    }
};

pub fn serviceOwner(state: *const BootstrapState, class: contract.ServiceClass) principal.PrincipalId {
    return session_bootstrap.ownerForServiceClass(state.ids, class) orelse unreachable;
}

pub fn serviceRecord(state: *const BootstrapState, class: contract.ServiceClass) *supervisor_mod.ServiceRecord {
    return session_bootstrap.serviceRecordForClass(state.services, class) orelse unreachable;
}

pub fn serviceId(state: *const BootstrapState, class: contract.ServiceClass) u64 {
    return serviceRecord(state, class).id;
}

pub const Environment = struct {
    capability_table: *capability.CapabilityTable,
    runtime: *task_runtime.Runtime,
    service_directory: *native_service_registry.Service,
    userspace_catalog: *userspace_loader.Catalog,
    userspace_scheduler: *userspace_scheduler.Scheduler,
    package_service: *package_service.Service,
    supervisor: *supervisor_mod.Supervisor,
    driver_directory: *driver_service.Directory,
    driver_runtime: *driver_runtime_mod.Runtime,
    diagnostic_ledger: *event_ledger.Ledger,
    background_dispatcher: *background_dispatch.Controller,
};

pub fn hasGrantForKind(grants: []const policy_mediation.UserGrant, kind: manifest.PermissionKind) bool {
    for (grants) |grant| {
        if (grant.kind == kind and grant.allow) {
            return true;
        }
    }
    return false;
}
