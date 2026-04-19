const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const principal = @import("../core/principal.zig");

pub fn serviceBootstrapRights() capability.CapabilityRights {
    return .{
        .endpoint_create = true,
        .endpoint_connect = true,
        .ipc_peer = true,
    };
}

pub fn transportBootstrapRights() capability.CapabilityRights {
    return .{
        .endpoint_create = true,
        .endpoint_connect = true,
        .capability_query = true,
        .shared_memory_create = true,
        .time_query = true,
        .resource_query = true,
        .accounting_query = true,
        .ipc_peer = true,
    };
}

pub fn deriveTaskCapability(
    kernel_port: *component_port.KernelPort,
    controller_task_id: u64,
    parent_capability_id: u64,
    target_task_id: u64,
    rights: capability.CapabilityRights,
    correlation_id: u64,
    now_ticks: u64,
) component_port.Error!u64 {
    const parent = kernel_port.kernel.capability_table.query(parent_capability_id) orelse return error.CapabilityNotFound;
    const target_task = kernel_port.kernel.runtime.find(target_task_id) orelse return error.TaskNotFound;
    const derived = try kernel_port.capabilityDerive(.{
        .header = component_port.makeHeader(.capability_derive, correlation_id, controller_task_id),
        .request = .{
            .parent_capability_id = parent_capability_id,
            .holder = target_task.owner,
            .rights = rights,
            .scope = taskScopedScope(parent.scope, target_task_id),
            .lease = .{
                .issued_at_ticks = now_ticks,
                .expires_at_ticks = parent.lease.expires_at_ticks,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = parent.audit.policy_generation,
                .source_task_id = controller_task_id,
                .broker_service_id = parent.audit.broker_service_id,
            },
        },
    });
    return derived.capability_id;
}

pub fn mintTaskCapability(
    kernel_port: *component_port.KernelPort,
    controller_task_id: u64,
    policy_capability_id: u64,
    target_task_id: u64,
    target: capability.CapabilityTarget,
    rights: capability.CapabilityRights,
    issuer: principal.PrincipalId,
    correlation_id: u64,
    now_ticks: u64,
) component_port.Error!u64 {
    const policy_capability = kernel_port.kernel.capability_table.query(policy_capability_id) orelse return error.CapabilityNotFound;
    const target_task = kernel_port.kernel.runtime.find(target_task_id) orelse return error.TaskNotFound;
    const minted = try kernel_port.capabilityMint(.{
        .header = component_port.makeHeader(.capability_mint, correlation_id, controller_task_id),
        .policy_capability_id = policy_capability_id,
        .request = .{
            .holder = target_task.owner,
            .issuer = issuer,
            .target = target,
            .rights = rights,
            .scope = taskScopedScope(policy_capability.scope, target_task_id),
            .lease = .{
                .issued_at_ticks = now_ticks,
                .expires_at_ticks = policy_capability.lease.expires_at_ticks,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = policy_capability.audit.policy_generation,
                .source_task_id = controller_task_id,
                .broker_service_id = policy_capability.audit.broker_service_id,
            },
        },
    }, now_ticks);
    return minted.capability_id;
}

fn taskScopedScope(parent_scope: capability.CapabilityScope, task_id: u64) capability.CapabilityScope {
    return .{
        .task_id = task_id,
        .workspace_id = parent_scope.workspace_id,
        .local_only = parent_scope.local_only,
        .broker_only = parent_scope.broker_only,
    };
}
