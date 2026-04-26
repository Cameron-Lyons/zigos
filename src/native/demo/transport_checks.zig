const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const bootstrap_capabilities = @import("../session/bootstrap_capabilities.zig");
const component_port = @import("../kernel_api/component_port.zig");
const kernel_descriptors = @import("../kernel_api/native_kernel_descriptors.zig");
const support = @import("../session/session_manager_support.zig");
const userspace_launch = @import("../task/userspace_launch.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

fn executeUserspaceProbe(env: *const support.Environment, task_id: u64) void {
    _ = env.userspace_scheduler.executeTask(task_id, 0);
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
        env.userspace_scheduler,
    ) catch unreachable;
    const storage_authority_capability_id = bootstrap_capabilities.deriveTaskCapability(
        kernel_port,
        state.session_task.id,
        state.session_capability.id,
        storage_task_desc.task_id,
        bootstrap_capabilities.serviceBootstrapRights(),
        3,
        3,
    ) catch unreachable;
    executeUserspaceProbe(env, storage_task_desc.task_id);
    const transport_probe_task = userspace_launch.launchRegisteredKernel(
        env.userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = state.session_capability.id,
            .controller_task_id = state.session_task.id,
            .correlation_id = 2,
            .now_ticks = 2,
        },
        "zigos.system.transport-probe",
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
        env.userspace_scheduler,
    ) catch unreachable;
    const transport_probe_authority_id = bootstrap_capabilities.deriveTaskCapability(
        kernel_port,
        state.session_task.id,
        state.session_capability.id,
        transport_probe_task.task_id,
        bootstrap_capabilities.transportBootstrapRights(),
        4,
        4,
    ) catch unreachable;
    common.printBootMarker(boot_markers.transport_task_create_ok);

    const storage_endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 3, storage_task_desc.task_id),
        .authority_capability_id = storage_authority_capability_id,
        .owner_task_id = storage_task_desc.task_id,
        .label = support.bootstrap_storage_interface.name,
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, 3) catch unreachable;
    common.printBootMarker("ZIGOS:TRANSPORT:ENDPOINT_CREATE:OK");
    const storage_record = env.runtime.find(storage_task_desc.task_id) orelse unreachable;
    env.service_directory.register(
        state.services.storage_service.id,
        storage_task_desc.task_id,
        storage_endpoint.endpoint.endpoint_id,
        support.bootstrap_storage_interface,
        kernel_descriptors.serviceBindingFlags(storage_record),
    ) catch unreachable;
    common.printBootMarker("ZIGOS:TRANSPORT:SERVICE_REGISTER:OK");

    const transport_probe_endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 5, transport_probe_task.task_id),
        .authority_capability_id = transport_probe_authority_id,
        .owner_task_id = transport_probe_task.task_id,
        .label = "transport.probe",
        .flags = .{ .local_only = true },
    }, 4) catch unreachable;
    const storage_connection = env.service_directory.connect(support.bootstrap_storage_interface) catch unreachable;
    _ = kernel_port.endpointConnect(.{
        .header = component_port.makeHeader(.endpoint_connect, 6, transport_probe_task.task_id),
        .endpoint_capability_id = transport_probe_endpoint.capability_id,
        .peer_endpoint_id = storage_connection.endpoint_id,
    }, 4) catch unreachable;
    env.runtime.audit(transport_probe_task.task_id, .{
        .kind = .service_connected,
        .detail = @truncate(storage_connection.service_id),
        .tick = 4,
    }) catch unreachable;
    common.printBootMarker(boot_markers.transport_service_connect_ok);

    const transport_probe_shm = kernel_port.sharedMemoryCreate(.{
        .header = component_port.makeHeader(.shared_memory_create, 7, transport_probe_task.task_id),
        .authority_capability_id = transport_probe_authority_id,
        .owner_task_id = transport_probe_task.task_id,
        .size_bytes = 4096,
    }, 5) catch unreachable;
    _ = kernel_port.sharedMemoryMap(.{
        .header = component_port.makeHeader(.shared_memory_map, 8, transport_probe_task.task_id),
        .shared_memory_capability_id = transport_probe_shm.capability_id,
        .task_id = transport_probe_task.task_id,
    }, 5) catch unreachable;
    common.printBootMarker("ZIGOS:TRANSPORT:SHM:MAP_OK");

    kernel_port.endpointSend(.{
        .header = component_port.makeHeader(.endpoint_send, 41, transport_probe_task.task_id),
        .endpoint_capability_id = transport_probe_endpoint.capability_id,
        .payload = "workspace-open",
        .attached_capability_id = transport_probe_shm.capability_id,
        .move_attached_capability = false,
    }, 6) catch unreachable;
    const transport_probe_received = kernel_port.endpointRecv(.{
        .header = component_port.makeHeader(.endpoint_recv, 9, storage_task_desc.task_id),
        .endpoint_capability_id = storage_endpoint.capability_id,
        .receiver_task_id = storage_task_desc.task_id,
    }, 7) catch unreachable orelse unreachable;
    if (std.mem.eql(u8, transport_probe_received.payload[0..transport_probe_received.payload_len], "workspace-open") and
        transport_probe_received.attached_capability != null)
    {
        common.printBootMarker(boot_markers.transport_cap_pass_ok);
    }

    const transport_probe_resources = kernel_port.resourceQuery(.{
        .header = component_port.makeHeader(.resource_query, 10, transport_probe_task.task_id),
        .authority_capability_id = transport_probe_authority_id,
        .task_id = transport_probe_task.task_id,
    }, 7) catch unreachable;
    if (transport_probe_resources.endpoint_count == 1) {
        common.printBootMarker("ZIGOS:TRANSPORT:RESOURCE_QUERY:OK");
    }
    const transport_probe_accounting = kernel_port.accountingQuery(.{
        .header = component_port.makeHeader(.accounting_query, 11, transport_probe_task.task_id),
        .authority_capability_id = transport_probe_authority_id,
        .task_id = transport_probe_task.task_id,
    }, 7) catch unreachable;
    if (transport_probe_accounting.audit_event_count != 0) {
        common.printBootMarker("ZIGOS:TRANSPORT:ACCOUNTING_QUERY:OK");
    }
    if ((kernel_port.timeQuery(.{
        .header = component_port.makeHeader(.time_query, 12, transport_probe_task.task_id),
        .authority_capability_id = transport_probe_authority_id,
    }, 7) catch unreachable) == 7) {
        common.printBootMarker("ZIGOS:TRANSPORT:TIME_QUERY:OK");
    }

    const derivable_capability = kernel_port.capabilityMint(.{
        .header = component_port.makeHeader(.capability_mint, 13, state.session_task.id),
        .policy_capability_id = state.policy_capability.id,
        .request = .{
            .holder = env.runtime.find(transport_probe_task.task_id).?.owner,
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
                .task_id = transport_probe_task.task_id,
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
                .source_task_id = transport_probe_task.task_id,
                .broker_service_id = state.services.policy_service.id,
            },
        },
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:TRANSPORT:CAP_MINT:OK");
    _ = kernel_port.capabilityQuery(.{
        .header = component_port.makeHeader(.capability_query, 14, transport_probe_task.task_id),
        .authority_capability_id = transport_probe_authority_id,
        .capability_id = derivable_capability.capability_id,
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:TRANSPORT:CAP_QUERY:OK");

    _ = kernel_port.capabilityDerive(.{
        .header = component_port.makeHeader(.capability_derive, 15, transport_probe_task.task_id),
        .request = .{
            .parent_capability_id = derivable_capability.capability_id,
            .holder = env.runtime.find(transport_probe_task.task_id).?.owner,
            .rights = .{ .object_read = true },
            .scope = .{
                .task_id = transport_probe_task.task_id,
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
                .source_task_id = transport_probe_task.task_id,
                .broker_service_id = state.services.policy_service.id,
            },
        },
    }) catch unreachable;
    common.printBootMarker("ZIGOS:TRANSPORT:CAP_DERIVE:OK");
    kernel_port.capabilityRevoke(.{
        .header = component_port.makeHeader(.capability_revoke, 16, state.session_task.id),
        .authority_capability_id = state.policy_capability.id,
        .capability_id = derivable_capability.capability_id,
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:TRANSPORT:CAP_REVOKE:OK");

    const termination_probe_task = userspace_launch.launchRegisteredKernel(
        env.userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = state.session_capability.id,
            .controller_task_id = state.session_task.id,
            .correlation_id = 17,
            .now_ticks = 8,
        },
        "zigos.system.termination-probe",
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
        env.userspace_scheduler,
    ) catch unreachable;
    const termination_probe_capability_id = bootstrap_capabilities.mintTaskCapability(
        kernel_port,
        state.session_task.id,
        state.policy_capability.id,
        termination_probe_task.task_id,
        .{ .kind = .task, .id = termination_probe_task.task_id },
        .{ .task_terminate = true },
        state.ids.policy_authority,
        18,
        8,
    ) catch unreachable;
    _ = kernel_port.taskTerminate(.{
        .header = component_port.makeHeader(.task_terminate, 19, termination_probe_task.task_id),
        .task_capability_id = termination_probe_capability_id,
    }, 9) catch unreachable;
    common.printBootMarker("ZIGOS:TRANSPORT:TASK_TERMINATE:OK");
}
