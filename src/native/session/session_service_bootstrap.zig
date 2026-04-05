const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const component_port = @import("../kernel_api/component_port.zig");
const contract = @import("contract.zig");
const driver_service = @import("../drivers/driver_service.zig");
const service_bootstrap = @import("service_bootstrap.zig");
const principal = @import("../core/principal.zig");
const service_contract = @import("service_contracts.zig");
const storage_volume_mod = @import("../storage/storage_volume.zig");
const support = @import("session_manager_support.zig");
const userspace_launch = @import("../task/userspace_launch.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

pub fn run(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *support.ServiceBindings,
) void {
    bootServices(env, state, kernel_port, service_bindings);
    connectClient(env, state, kernel_port, service_bindings);
    recordDriverRecovery(env, state, service_bindings);
}

pub fn bootServices(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *support.ServiceBindings,
) void {
    @call(.never_inline, launchServices, .{ env, state, kernel_port, service_bindings });
    @call(.never_inline, activateDrivers, .{ env, state, kernel_port, service_bindings });
}

fn launchServices(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *support.ServiceBindings,
) void {
    service_bindings.* = .{ .bindings = undefined };
    for (service_contract.ordered_service_contracts, 0..) |entry, index| {
        service_bindings.bindings[index] = service_bootstrap.launchContractService(
            env.userspace_catalog,
            kernel_port,
            env.supervisor,
            state.session_capability.id,
            state.session_task.id,
            env.userspace_scheduler,
            serviceOwner(state, entry.class),
            serviceId(state, entry.class),
            entry,
            entry.boot_correlation_base,
            entry.boot_tick,
        ) catch unreachable;
        if (entry.class == .compatibility_portal) {
            common.printBootMarker("ZIGOS:SERVICE_BOOT:COMPAT_PORTAL:READY");
        }
    }
}

fn activateDrivers(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *const support.ServiceBindings,
) void {
    const storage_driver_task = service_bootstrap.launchDriverTask(
        env.userspace_catalog,
        kernel_port,
        state.session_capability.id,
        state.session_task.id,
        env.userspace_scheduler,
        state.ids.storage_service,
        "zigos.system.storage-driver",
        .storage_controller,
        328,
        52,
    ) catch unreachable;

    const network_driver = service_bootstrap.attachDriver(
        kernel_port,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        state.policy_capability.id,
        state.services.network_service.id,
        service_bindings.bindingFor(.network_stack).task_id,
        state.ids.network_service,
        .network_adapter,
        .kernel_published_data_plane,
        "zigos.system.network-stack",
        53,
    );
    const storage_driver = service_bootstrap.attachDriver(
        kernel_port,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        state.policy_capability.id,
        state.services.storage_service.id,
        storage_driver_task.task_id,
        state.ids.storage_service,
        .storage_controller,
        .kernel_published_data_plane,
        "zigos.system.storage-driver",
        54,
    );
    _ = service_bootstrap.attachDriver(
        kernel_port,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        state.policy_capability.id,
        state.services.compositor_service.id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        state.ids.compositor_service,
        .graphics_adapter,
        .none,
        "zigos.system.compositor",
        55,
    );
    _ = service_bootstrap.attachDriver(
        kernel_port,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        state.policy_capability.id,
        state.services.media_service.id,
        service_bindings.bindingFor(.media_print_helpers).task_id,
        state.ids.media_service,
        .audio_print_io,
        .none,
        "zigos.system.media-print",
        56,
    );

    const network_activation_mode = env.driver_runtime.activateModeAt(network_driver, 53) catch unreachable;
    const storage_activation_mode = env.driver_runtime.activateModeAt(storage_driver, 54) catch unreachable;
    if ((network_activation_mode == .published_data_plane or env.driver_directory.findByClass(.network_adapter) != null) and
        (storage_activation_mode == .published_data_plane or storage_driver.restart_generation == 1))
    {
        common.printBootMarker(boot_markers.service_boot_driver_service_network_ready);
    }
    if (storage_activation_mode == .published_data_plane and storage_volume_mod.hasAttachedDevice()) {
        common.printBootMarker("ZIGOS:SERVICE_BOOT:DRIVER_SERVICE:STORAGE_READY");
    }

    if (service_bootstrap.contractsReady(env.service_directory)) {
        common.printBootMarker(boot_markers.service_boot_service_contracts_ready);
    }
}

fn connectClient(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *const support.ServiceBindings,
) void {
    const service_client_task = userspace_launch.launchRegisteredKernel(
        env.userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = state.session_capability.id,
            .controller_task_id = state.session_task.id,
            .correlation_id = 330,
            .now_ticks = 56,
        },
        "zigos.system.service-client",
        .{
            .owner = .{ .kind = .app, .serial = 20 },
            .budget = .{
                .cpu_time_ticks = 6_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 16,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        env.userspace_scheduler,
    ) catch unreachable;
    if (!env.runtime.hasCapability(service_client_task.task_id, state.session_capability.id)) {
        env.runtime.grantCapability(service_client_task.task_id, state.session_capability.id) catch unreachable;
    }

    var service_connect_count: usize = 0;
    for (service_contract.ordered_service_contracts, service_bindings.bindings, 0..) |entry, binding, index| {
        const endpoint_request_id = 331 + @as(u64, @intCast(index * 2));
        const connect_request_id = endpoint_request_id + 1;
        const client_endpoint = kernel_port.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, endpoint_request_id, service_client_task.task_id),
            .authority_capability_id = state.session_capability.id,
            .owner_task_id = service_client_task.task_id,
            .label = entry.interface.name,
            .flags = .{ .local_only = true },
        }, 57 + @as(u64, @intCast(index))) catch unreachable;
        const registry_connection = env.service_directory.connect(entry.interface) catch unreachable;
        _ = kernel_port.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, connect_request_id, service_client_task.task_id),
            .endpoint_capability_id = client_endpoint.capability_id,
            .peer_endpoint_id = binding.endpoint_id,
        }, 57 + @as(u64, @intCast(index))) catch unreachable;
        env.runtime.audit(service_client_task.task_id, .{
            .kind = .service_connected,
            .detail = @truncate(registry_connection.service_id),
            .tick = 57 + @as(u64, @intCast(index)),
        }) catch unreachable;
        if (registry_connection.service_id == env.supervisor.findByClass(entry.class).?.id) {
            service_connect_count += 1;
        }
    }
    if (service_connect_count == service_contract.ordered_service_contracts.len) {
        common.printBootMarker(boot_markers.service_boot_ipc_connect_all_ok);
    }
}

fn recordDriverRecovery(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    service_bindings: *const support.ServiceBindings,
) void {
    _ = env.supervisor.recoverDriverCrash(
        state.services.network_service.id,
        env.driver_directory,
        env.driver_runtime,
        null,
        env.diagnostic_ledger,
        70,
        0x4E,
        "network driver restarted",
    ) catch unreachable;
    if (env.supervisor.hasDiagnostic(state.services.network_service.id, .crash)) {
        common.printBootMarker("ZIGOS:SERVICE_BOOT:SUPERVISOR:CRASH_RECORDED");
    }
    env.runtime.audit(service_bindings.bindingFor(.network_stack).task_id, .{
        .kind = .service_restarted,
        .detail = @truncate(state.services.network_service.id),
        .tick = 72,
    }) catch unreachable;
    if (env.supervisor.hasDiagnostic(state.services.network_service.id, .restart_completed) and
        env.driver_directory.findByService(state.services.network_service.id).?.restart_generation == 2)
    {
        common.printBootMarker(boot_markers.service_boot_supervisor_restart_ok);
    }
}

fn serviceOwner(state: *const support.BootstrapState, class: contract.ServiceClass) principal.PrincipalId {
    return switch (class) {
        .policy_mediation => state.ids.policy_authority,
        .network_stack => state.ids.network_service,
        .storage_object => state.ids.storage_service,
        .package_install_update => state.ids.package_service,
        .compositor_ui_session => state.ids.compositor_service,
        .indexing_search => state.ids.indexing_service,
        .sync_replication => state.ids.sync_service,
        .media_print_helpers => state.ids.media_service,
        .compatibility_portal => state.ids.compatibility_service,
        else => unreachable,
    };
}

fn serviceId(state: *const support.BootstrapState, class: contract.ServiceClass) u64 {
    return switch (class) {
        .policy_mediation => state.services.policy_service.id,
        .network_stack => state.services.network_service.id,
        .storage_object => state.services.storage_service.id,
        .package_install_update => state.services.package_service.id,
        .compositor_ui_session => state.services.compositor_service.id,
        .indexing_search => state.services.indexing_service.id,
        .sync_replication => state.services.sync_service.id,
        .media_print_helpers => state.services.media_service.id,
        .compatibility_portal => state.services.compatibility_service.id,
        else => unreachable,
    };
}
