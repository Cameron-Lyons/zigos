const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const component_port = @import("../kernel_api/component_port.zig");
const support = @import("session_manager_support.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_launch = @import("../task/userspace_launch.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

fn scheduleUserspaceTask(task_id: u64) bool {
    return userspace_scheduler.registerTask(task_id);
}

fn executeUserspaceProbe(env: *const support.Environment, task_id: u64) void {
    _ = userspace_executor.executeTask(env.userspace_catalog, env.runtime, env.capability_table, task_id, 0);
}

fn grantTaskCapability(env: *const support.Environment, task_id: u64, capability_id: u64) void {
    if (!env.runtime.hasCapability(task_id, capability_id)) {
        env.runtime.grantCapability(task_id, capability_id) catch unreachable;
    }
}

pub fn run(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
) void {
    const storage_task_desc = userspace_launch.launchRegisteredKernel(
        env.userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = state.session_capability.id,
            .controller_task_id = state.session_task.id,
            .correlation_id = 1,
            .now_ticks = 1,
        },
        "zigos.system.workspace-storage",
        .{
            .owner = state.ids.storage_service,
            .budget = .{
                .cpu_time_ticks = 8_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 6,
                .shared_memory_bytes = 128 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    grantTaskCapability(env, storage_task_desc.task_id, state.session_capability.id);
    executeUserspaceProbe(env, storage_task_desc.task_id);
    const phase1_client_task_desc = userspace_launch.launchRegisteredKernel(
        env.userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = state.session_capability.id,
            .controller_task_id = state.session_task.id,
            .correlation_id = 2,
            .now_ticks = 2,
        },
        "zigos.system.phase1-client",
        .{
            .owner = .{ .kind = .app, .serial = 10 },
            .budget = .{
                .cpu_time_ticks = 6_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 6,
                .shared_memory_bytes = 128 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    grantTaskCapability(env, phase1_client_task_desc.task_id, state.session_capability.id);
    grantTaskCapability(env, phase1_client_task_desc.task_id, state.policy_capability.id);
    common.printBootMarker(boot_markers.phase1_task_create_ok);

    const storage_endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 3, storage_task_desc.task_id),
        .authority_capability_id = state.session_capability.id,
        .owner_task_id = storage_task_desc.task_id,
        .label = support.bootstrap_storage_interface.name,
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, 3) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:ENDPOINT_CREATE:OK");
    kernel_port.serviceRegister(.{
        .header = component_port.makeHeader(.service_register, 4, storage_task_desc.task_id),
        .authority_capability_id = state.session_capability.id,
        .service_id = state.services.storage_service.id,
        .owner_task_id = storage_task_desc.task_id,
        .endpoint_capability_id = storage_endpoint.capability_id,
        .interface = support.bootstrap_storage_interface,
    }, 3) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:SERVICE_REGISTER:OK");

    const phase1_client_endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 5, phase1_client_task_desc.task_id),
        .authority_capability_id = state.session_capability.id,
        .owner_task_id = phase1_client_task_desc.task_id,
        .label = "phase1.client",
        .flags = .{ .local_only = true },
    }, 4) catch unreachable;
    _ = kernel_port.serviceConnect(.{
        .header = component_port.makeHeader(.service_connect, 6, phase1_client_task_desc.task_id),
        .authority_capability_id = state.session_capability.id,
        .endpoint_capability_id = phase1_client_endpoint.capability_id,
        .interface = support.bootstrap_storage_interface,
    }, 4) catch unreachable;
    common.printBootMarker(boot_markers.phase1_service_connect_ok);

    const phase1_shm = kernel_port.sharedMemoryCreate(.{
        .header = component_port.makeHeader(.shared_memory_create, 7, phase1_client_task_desc.task_id),
        .authority_capability_id = state.session_capability.id,
        .owner_task_id = phase1_client_task_desc.task_id,
        .size_bytes = 4096,
    }, 5) catch unreachable;
    _ = kernel_port.sharedMemoryMap(.{
        .header = component_port.makeHeader(.shared_memory_map, 8, phase1_client_task_desc.task_id),
        .shared_memory_capability_id = phase1_shm.capability_id,
        .task_id = phase1_client_task_desc.task_id,
    }, 5) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:SHM:MAP_OK");

    kernel_port.endpointSend(.{
        .header = component_port.makeHeader(.endpoint_send, 41, phase1_client_task_desc.task_id),
        .endpoint_capability_id = phase1_client_endpoint.capability_id,
        .payload = "workspace-open",
        .attached_capability_id = phase1_shm.capability_id,
        .move_attached_capability = false,
    }, 6) catch unreachable;
    const phase1_received = kernel_port.endpointRecv(.{
        .header = component_port.makeHeader(.endpoint_recv, 9, storage_task_desc.task_id),
        .endpoint_capability_id = storage_endpoint.capability_id,
        .receiver_task_id = storage_task_desc.task_id,
    }, 7) catch unreachable orelse unreachable;
    if (std.mem.eql(u8, phase1_received.payload[0..phase1_received.payload_len], "workspace-open") and
        phase1_received.attached_capability != null)
    {
        common.printBootMarker(boot_markers.phase1_cap_pass_ok);
    }

    const phase1_resources = kernel_port.resourceQuery(.{
        .header = component_port.makeHeader(.resource_query, 10, phase1_client_task_desc.task_id),
        .authority_capability_id = state.session_capability.id,
        .task_id = phase1_client_task_desc.task_id,
    }, 7) catch unreachable;
    if (phase1_resources.endpoint_count == 1) {
        common.printBootMarker("ZIGOS:PHASE1:RESOURCE_QUERY:OK");
    }
    const phase1_accounting = kernel_port.accountingQuery(.{
        .header = component_port.makeHeader(.accounting_query, 11, phase1_client_task_desc.task_id),
        .authority_capability_id = state.session_capability.id,
        .task_id = phase1_client_task_desc.task_id,
    }, 7) catch unreachable;
    if (phase1_accounting.audit_event_count != 0) {
        common.printBootMarker("ZIGOS:PHASE1:ACCOUNTING_QUERY:OK");
    }
    if ((kernel_port.timeQuery(.{
        .header = component_port.makeHeader(.time_query, 12, phase1_client_task_desc.task_id),
        .authority_capability_id = state.session_capability.id,
    }, 7) catch unreachable) == 7) {
        common.printBootMarker("ZIGOS:PHASE1:TIME_QUERY:OK");
    }

    const derivable_capability = kernel_port.capabilityMint(.{
        .header = component_port.makeHeader(.capability_mint, 13, phase1_client_task_desc.task_id),
        .policy_capability_id = state.policy_capability.id,
        .request = .{
            .holder = env.runtime.find(phase1_client_task_desc.task_id).?.owner,
            .issuer = state.ids.policy_authority,
            .target = .{ .kind = .object, .id = 0xCAFE },
            .rights = .{
                .object_read = true,
                .object_write = true,
                .capability_derive = true,
                .capability_query = true,
                .capability_revoke = true,
                .capability_pass = true,
            },
            .scope = .{
                .task_id = phase1_client_task_desc.task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 7,
                .expires_at_ticks = 100,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = phase1_client_task_desc.task_id,
                .broker_service_id = state.services.policy_service.id,
            },
        },
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_MINT:OK");
    _ = kernel_port.capabilityQuery(.{
        .header = component_port.makeHeader(.capability_query, 14, phase1_client_task_desc.task_id),
        .authority_capability_id = state.session_capability.id,
        .capability_id = derivable_capability.capability_id,
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_QUERY:OK");

    _ = kernel_port.capabilityDerive(.{
        .header = component_port.makeHeader(.capability_derive, 15, phase1_client_task_desc.task_id),
        .request = .{
            .parent_capability_id = derivable_capability.capability_id,
            .holder = env.runtime.find(phase1_client_task_desc.task_id).?.owner,
            .rights = .{ .object_read = true },
            .scope = .{
                .task_id = phase1_client_task_desc.task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 7,
                .expires_at_ticks = 60,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = phase1_client_task_desc.task_id,
                .broker_service_id = state.services.policy_service.id,
            },
        },
    }) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_DERIVE:OK");
    kernel_port.capabilityRevoke(.{
        .header = component_port.makeHeader(.capability_revoke, 16, phase1_client_task_desc.task_id),
        .authority_capability_id = state.policy_capability.id,
        .capability_id = derivable_capability.capability_id,
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_REVOKE:OK");

    const phase1_temp_task = userspace_launch.launchRegisteredKernel(
        env.userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = state.session_capability.id,
            .controller_task_id = state.session_task.id,
            .correlation_id = 17,
            .now_ticks = 8,
        },
        "zigos.system.phase1-temp",
        .{
            .owner = .{ .kind = .app, .serial = 11 },
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 128 * 1024,
                .endpoint_slots = 2,
                .shared_memory_bytes = 32 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    grantTaskCapability(env, phase1_temp_task.task_id, state.policy_capability.id);
    const phase1_temp_capability = kernel_port.capabilityMint(.{
        .header = component_port.makeHeader(.capability_mint, 18, phase1_temp_task.task_id),
        .policy_capability_id = state.policy_capability.id,
        .request = .{
            .holder = env.runtime.find(phase1_temp_task.task_id).?.owner,
            .issuer = state.ids.policy_authority,
            .target = .{ .kind = .task, .id = phase1_temp_task.task_id },
            .rights = .{ .task_terminate = true },
            .scope = .{
                .task_id = phase1_temp_task.task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 8,
                .expires_at_ticks = 50,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = phase1_temp_task.task_id,
                .broker_service_id = state.services.policy_service.id,
            },
        },
    }, 8) catch unreachable;
    _ = kernel_port.taskTerminate(.{
        .header = component_port.makeHeader(.task_terminate, 19, phase1_temp_task.task_id),
        .task_capability_id = phase1_temp_capability.capability_id,
    }, 9) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:TASK_TERMINATE:OK");
}
