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
) support.ServiceBindings {
    var service_bindings = bootServices(env, state, kernel_port);
    connectClient(env, state, kernel_port, &service_bindings);
    recordDriverRecovery(env, state, &service_bindings);
    return service_bindings;
}

pub fn bootServices(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
) support.ServiceBindings {
    var service_bindings = launchServices(env, state, kernel_port);
    activateDrivers(env, state, kernel_port, &service_bindings);
    return service_bindings;
}

fn launchServices(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
) support.ServiceBindings {
    const service_launch_specs: [service_contract.ordered_service_contracts.len]struct {
        owner: principal.PrincipalId,
        service_id: u64,
        correlation_base: u64,
        now_ticks: u64,
    } = .{
        .{ .owner = state.ids.policy_authority, .service_id = state.services.policy_service.id, .correlation_base = 301, .now_ticks = 31 },
        .{ .owner = state.ids.network_service, .service_id = state.services.network_service.id, .correlation_base = 304, .now_ticks = 34 },
        .{ .owner = state.ids.storage_service, .service_id = state.services.storage_service.id, .correlation_base = 307, .now_ticks = 35 },
        .{ .owner = state.ids.package_service, .service_id = state.services.package_service.id, .correlation_base = 310, .now_ticks = 38 },
        .{ .owner = state.ids.compositor_service, .service_id = state.services.compositor_service.id, .correlation_base = 313, .now_ticks = 41 },
        .{ .owner = state.ids.indexing_service, .service_id = state.services.indexing_service.id, .correlation_base = 316, .now_ticks = 44 },
        .{ .owner = state.ids.sync_service, .service_id = state.services.sync_service.id, .correlation_base = 319, .now_ticks = 47 },
        .{ .owner = state.ids.media_service, .service_id = state.services.media_service.id, .correlation_base = 322, .now_ticks = 50 },
    };

    var service_bindings = support.ServiceBindings{ .bindings = undefined };
    for (service_contract.ordered_service_contracts, service_launch_specs, 0..) |entry, spec, index| {
        service_bindings.bindings[index] = service_bootstrap.launchContractService(
            env.userspace_catalog,
            kernel_port,
            env.supervisor,
            state.session_capability.id,
            state.session_task.id,
            env.userspace_scheduler,
            spec.owner,
            spec.service_id,
            entry,
            spec.correlation_base,
            spec.now_ticks,
        );
    }

    _ = service_bootstrap.launchBundleService(
        env.userspace_catalog,
        kernel_port,
        env.supervisor,
        state.session_capability.id,
        state.session_task.id,
        env.userspace_scheduler,
        state.ids.compatibility_service,
        state.services.compatibility_service.id,
        "zigos.system.compatibility-portal",
        support.compatibility_portal_interface,
        service_bootstrap.serviceBudget(.compatibility_portal),
        325,
        51,
    );
    common.printBootMarker("ZIGOS:SERVICE_BOOT:COMPAT_PORTAL:READY");

    return service_bindings;
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
    );

    const driver_specs = [_]struct {
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        device_class: driver_service.DeviceClass,
        bootstrap_transport: driver_service.BootstrapTransport,
        driver_bundle_id: []const u8,
        now_ticks: u64,
    }{
        .{ .service_id = state.services.network_service.id, .task_id = service_bindings.bindingFor(.network_stack).task_id, .owner = state.ids.network_service, .device_class = .network_adapter, .bootstrap_transport = .kernel_published_data_plane, .driver_bundle_id = "zigos.system.network-stack", .now_ticks = 53 },
        .{ .service_id = state.services.storage_service.id, .task_id = storage_driver_task.task_id, .owner = state.ids.storage_service, .device_class = .storage_controller, .bootstrap_transport = .kernel_published_data_plane, .driver_bundle_id = "zigos.system.storage-driver", .now_ticks = 54 },
        .{ .service_id = state.services.compositor_service.id, .task_id = service_bindings.bindingFor(.compositor_ui_session).task_id, .owner = state.ids.compositor_service, .device_class = .graphics_adapter, .bootstrap_transport = .none, .driver_bundle_id = "zigos.system.compositor", .now_ticks = 55 },
        .{ .service_id = state.services.media_service.id, .task_id = service_bindings.bindingFor(.media_print_helpers).task_id, .owner = state.ids.media_service, .device_class = .audio_print_io, .bootstrap_transport = .none, .driver_bundle_id = "zigos.system.media-print", .now_ticks = 56 },
    };

    var drivers: [driver_specs.len]*driver_service.DriverRecord = undefined;
    for (driver_specs, 0..) |spec, index| {
        drivers[index] = service_bootstrap.attachDriver(
            kernel_port,
            env.capability_table,
            env.driver_directory,
            env.supervisor,
            state.ids.policy_authority,
            state.policy_capability.id,
            spec.service_id,
            spec.task_id,
            spec.owner,
            spec.device_class,
            spec.bootstrap_transport,
            spec.driver_bundle_id,
            spec.now_ticks,
        );
    }

    const network_driver = drivers[0];
    const storage_driver = drivers[1];
    const network_activation = env.driver_runtime.activateAt(network_driver, 53) catch unreachable;
    const storage_activation = env.driver_runtime.activateAt(storage_driver, 54) catch unreachable;
    _ = env.driver_runtime.activateAt(env.driver_directory.findByClass(.graphics_adapter).?, 55) catch unreachable;
    _ = env.driver_runtime.activateAt(env.driver_directory.findByClass(.audio_print_io).?, 56) catch unreachable;
    if ((network_activation.mode == .published_data_plane or env.driver_directory.findByClass(.network_adapter) != null) and
        (storage_activation.mode == .published_data_plane or storage_driver.restart_generation == 1))
    {
        common.printBootMarker(boot_markers.service_boot_driver_service_network_ready);
    }
    if (storage_activation.mode == .published_data_plane and storage_volume_mod.hasAttachedDevice()) {
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
    );
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
