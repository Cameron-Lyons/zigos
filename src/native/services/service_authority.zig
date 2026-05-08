const capability = @import("../kernel_api/capability.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");

pub const Context = struct {
    task_id: u64,
    principal: principal.PrincipalId,
    capability_id: u64,
    now_ticks: u64,
};

pub const Error = error{
    CapabilityRequired,
    CapabilityNotFound,
    CapabilityRevoked,
    PermissionDenied,
};

pub fn requireServiceAuthority(
    capability_table: *const capability.CapabilityTable,
    service_id: u64,
    authority_context: Context,
    required_right: capability.CapabilityRight,
) Error!*const capability.Capability {
    const authority = capability_table.requireUsable(authority_context.capability_id, authority_context.now_ticks) catch |err| switch (err) {
        error.CapabilityNotFound => return error.CapabilityNotFound,
        error.CapabilityRevoked => return error.CapabilityRevoked,
        else => native_util.impossibleByInvariantError("service authority lookup only reports not-found or revoked capabilities", err),
    };

    if (!authority.holder.eql(authority_context.principal)) return error.PermissionDenied;
    if (authority.scope.task_id) |scoped_task_id| {
        if (scoped_task_id != authority_context.task_id) return error.PermissionDenied;
    }
    if (authority.target.kind != .service or authority.target.id != service_id) {
        return error.CapabilityRequired;
    }
    if (!authority.rights.has(required_right)) return error.PermissionDenied;
    return authority;
}
