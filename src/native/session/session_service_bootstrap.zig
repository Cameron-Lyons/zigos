const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const bootstrap_capabilities = @import("bootstrap_capabilities.zig");
const component_port = @import("../kernel_api/component_port.zig");
const contract = @import("contract.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const device_inventory = @import("../drivers/device_inventory.zig");
const driver_service = @import("../drivers/driver_service.zig");
const native_util = @import("../core/util.zig");
const std = @import("std");
const service_bootstrap = @import("service_bootstrap.zig");
const principal = @import("../core/principal.zig");
const service_contract = @import("service_contracts.zig");
const root = @import("root");
const storage_volume_mod = if (builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume"))
    root.storage_volume
else
    @import("../storage/storage_volume.zig");
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
) bool {
    if (!bootServices(env, state, kernel_port, service_bindings)) return false;
    if (!connectClient(env, state, kernel_port, service_bindings)) return false;
    return recordDriverRecovery(env, state, service_bindings);
}

pub fn bootServices(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *support.ServiceBindings,
) bool {
    const env_snapshot = env.*;
    const state_snapshot = state.*;
    if (!@call(.never_inline, launchServices, .{ &env_snapshot, &state_snapshot, kernel_port, service_bindings })) return false;
    return @call(.never_inline, activateDrivers, .{ &env_snapshot, &state_snapshot, kernel_port, service_bindings });
}

pub fn bootRegistryService(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *support.ServiceBindings,
) bool {
    const index = service_contract.orderedIndex(.service_registry).?;
    if (service_bindings.bindings[index].task_id != 0) return true;
    const entry = service_contract.contractForClass(.service_registry).?;
    service_bindings.bindings[index] = launchService(env, state, kernel_port, entry) catch |err| {
        _ = env.supervisor.recordCrash(serviceId(state, entry.class), entry.boot_tick, bootFailureCode(err));
        return false;
    };
    return true;
}

fn launchServices(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *support.ServiceBindings,
) bool {
    for (service_contract.ordered_service_contracts, 0..) |entry, index| {
        if (service_bindings.bindings[index].task_id != 0) continue;
        service_bindings.bindings[index] = launchService(env, state, kernel_port, entry) catch |err| {
            _ = env.supervisor.recordCrash(serviceId(state, entry.class), entry.boot_tick, bootFailureCode(err));
            return false;
        };
        if (entry.class == .compatibility_portal) {
            common.printBootMarker("ZIGOS:SERVICE_BOOT:COMPAT_PORTAL:READY");
        }
    }
    return true;
}

fn launchService(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    entry: service_contract.ServiceContract,
) service_bootstrap.Error!service_bootstrap.ServiceBinding {
    try env.runtime.grantCapability(state.session_task.id, state.session_capability.id);
    return service_bootstrap.launchContractService(
        env.userspace_catalog,
        kernel_port,
        env.service_directory,
        env.supervisor,
        state.session_capability.id,
        if (entry.class == .service_registry) state.session_task.id else 0,
        env.userspace_scheduler,
        serviceOwner(state, entry.class),
        serviceId(state, entry.class),
        entry,
        entry.boot_correlation_base,
        entry.boot_tick,
    );
}

fn activateDrivers(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *const support.ServiceBindings,
) bool {
    const storage_driver_task = service_bootstrap.launchDriverTask(
        env.userspace_catalog,
        kernel_port,
        state.session_capability.id,
        0,
        env.userspace_scheduler,
        state.ids.storage_service,
        "zigos.system.storage-driver",
        .storage_controller,
        328,
        52,
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 52, bootFailureCode(err));
        return false;
    };

    const network_driver = service_bootstrap.attachDriver(
        kernel_port,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        state.policy_capability.id,
        0,
        state.services.network_service.id,
        service_bindings.bindingFor(.network_stack).task_id,
        state.ids.network_service,
        .network_adapter,
        .none,
        "zigos.system.network-stack",
        53,
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.network_service.id, 53, bootFailureCode(err));
        return false;
    };
    const storage_driver = service_bootstrap.attachDriver(
        kernel_port,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        state.policy_capability.id,
        0,
        state.services.storage_service.id,
        storage_driver_task.task_id,
        state.ids.storage_service,
        .storage_controller,
        .kernel_published_data_plane,
        "zigos.system.storage-driver",
        54,
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 54, bootFailureCode(err));
        return false;
    };
    const storage_inventory = device_inventory.recordForClass(.storage_controller);
    if (bootstrap_driver_port.storagePublication() == null and
        storage_inventory.detected and
        storage_inventory.source == .ata_bootstrap and
        !bootstrap_driver_port.claimStorageAtaBootstrapInventory(storage_driver, "zigos.system.storage-driver"))
    {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 54, bootFailureCode(error.InvalidBootstrapTransport));
        return false;
    }
    _ = service_bootstrap.attachDriver(
        kernel_port,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        state.policy_capability.id,
        0,
        state.services.compositor_service.id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        state.ids.compositor_service,
        .graphics_adapter,
        .none,
        "zigos.system.compositor",
        55,
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.compositor_service.id, 55, bootFailureCode(err));
        return false;
    };
    _ = service_bootstrap.attachDriver(
        kernel_port,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        state.policy_capability.id,
        0,
        state.services.media_service.id,
        service_bindings.bindingFor(.media_print_helpers).task_id,
        state.ids.media_service,
        .audio_print_io,
        .none,
        "zigos.system.media-print",
        56,
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.media_service.id, 56, bootFailureCode(err));
        return false;
    };

    const network_activation_mode = env.driver_runtime.activateModeAt(network_driver, 53) catch |err| {
        _ = env.supervisor.recordCrash(state.services.network_service.id, 53, bootFailureCode(err));
        return false;
    };
    const storage_activation_mode = env.driver_runtime.activateModeAt(storage_driver, 54) catch |err| {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 54, bootFailureCode(err));
        return false;
    };
    if ((network_activation_mode == .control_only or env.driver_directory.findByClass(.network_adapter) != null) and
        (storage_activation_mode == .published_data_plane or
            storage_activation_mode == .userspace_brokered_data_plane or
            storage_driver.restart_generation == 1))
    {
        common.printBootMarker(boot_markers.service_boot_driver_service_network_ready);
    }
    if ((storage_activation_mode == .published_data_plane or
        storage_activation_mode == .userspace_brokered_data_plane) and
        storage_volume_mod.hasAttachedDevice())
    {
        common.printBootMarker("ZIGOS:SERVICE_BOOT:DRIVER_SERVICE:STORAGE_READY");
    }

    if (service_bootstrap.contractsReady(env.service_directory)) {
        common.printBootMarker(boot_markers.service_boot_service_contracts_ready);
    }
    return true;
}

fn connectClient(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *const support.ServiceBindings,
) bool {
    const service_client_task = userspace_launch.launchRegisteredDirect(
        env.userspace_catalog,
        env.runtime,
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
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.service_registry.id, 56, bootFailureCode(err));
        return false;
    };
    const service_client_authority = env.capability_table.mintBootRoot(.{
        .holder = service_client_task.owner,
        .issuer = state.ids.policy_authority,
        .target = .{ .kind = .service, .id = state.services.service_registry.id },
        .rights = bootstrap_capabilities.serviceBootstrapRights(),
        .scope = .{
            .task_id = service_client_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 56,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = false,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = 0,
            .broker_service_id = state.services.service_registry.id,
        },
    }) catch |err| {
        _ = env.supervisor.recordCrash(state.services.service_registry.id, 56, bootFailureCode(err));
        return false;
    };
    env.runtime.grantCapability(service_client_task.id, service_client_authority.id) catch |err| {
        _ = env.supervisor.recordCrash(state.services.service_registry.id, 56, bootFailureCode(err));
        return false;
    };

    var service_connect_count: usize = 0;
    for (service_contract.ordered_service_contracts, service_bindings.bindings, 0..) |entry, binding, index| {
        const endpoint_request_id = 332 + @as(u64, @intCast(index * 2));
        const connect_request_id = endpoint_request_id + 1;
        const client_endpoint = kernel_port.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, endpoint_request_id, service_client_task.id),
            .authority_capability_id = service_client_authority.id,
            .owner_task_id = service_client_task.id,
            .label = entry.interface.name,
            .flags = .{ .local_only = true },
        }, 57 + @as(u64, @intCast(index))) catch |err| {
            _ = env.supervisor.recordCrash(serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), bootFailureCode(err));
            return false;
        };
        const registry_connection = env.service_directory.connect(entry.interface) catch |err| {
            _ = env.supervisor.recordCrash(serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), bootFailureCode(err));
            return false;
        };
        _ = kernel_port.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, connect_request_id, service_client_task.id),
            .endpoint_capability_id = client_endpoint.capability_id,
            .peer_endpoint_id = binding.endpoint_id,
        }, 57 + @as(u64, @intCast(index))) catch |err| {
            _ = env.supervisor.recordCrash(serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), bootFailureCode(err));
            return false;
        };
        env.runtime.audit(service_client_task.id, .{
            .kind = .service_connected,
            .detail = @truncate(registry_connection.service_id),
            .tick = 57 + @as(u64, @intCast(index)),
        }) catch |err| {
            _ = env.supervisor.recordCrash(serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), bootFailureCode(err));
            return false;
        };
        const service = env.supervisor.findByClass(entry.class) orelse return false;
        if (registry_connection.service_id == service.id) {
            service_connect_count += 1;
        }
    }
    if (service_connect_count == service_contract.ordered_service_contracts.len) {
        common.printBootMarker(boot_markers.service_boot_ipc_connect_all_ok);
    }
    return true;
}

fn recordDriverRecovery(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    service_bindings: *const support.ServiceBindings,
) bool {
    _ = env.supervisor.recoverDriverCrash(
        state.services.network_service.id,
        env.driver_directory,
        env.driver_runtime,
        null,
        env.diagnostic_ledger,
        70,
        0x4E,
        "network driver restarted",
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.network_service.id, 70, bootFailureCode(err));
        return false;
    };
    if (env.supervisor.hasDiagnostic(state.services.network_service.id, .crash)) {
        common.printBootMarker("ZIGOS:SERVICE_BOOT:SUPERVISOR:CRASH_RECORDED");
    }
    env.runtime.audit(service_bindings.bindingFor(.network_stack).task_id, .{
        .kind = .service_restarted,
        .detail = @truncate(state.services.network_service.id),
        .tick = 72,
    }) catch |err| {
        _ = env.supervisor.recordCrash(state.services.network_service.id, 72, bootFailureCode(err));
        return false;
    };
    if (env.supervisor.hasDiagnostic(state.services.network_service.id, .restart_completed) and
        (env.driver_directory.findByService(state.services.network_service.id) orelse return false).restart_generation == 2)
    {
        common.printBootMarker(boot_markers.service_boot_supervisor_restart_ok);
    }
    return true;
}

fn serviceOwner(state: *const support.BootstrapState, class: contract.ServiceClass) principal.PrincipalId {
    return switch (class) {
        .service_registry => state.ids.policy_authority,
        .policy_mediation => state.ids.policy_authority,
        .permission_review_ui => state.ids.review_service,
        .network_stack => state.ids.network_service,
        .storage_object => state.ids.storage_service,
        .package_install_update => state.ids.package_service,
        .compositor_ui_session => state.ids.compositor_service,
        .indexing_search => state.ids.indexing_service,
        .sync_replication => state.ids.sync_service,
        .media_print_helpers => state.ids.media_service,
        .compatibility_portal => state.ids.compatibility_service,
        else => native_util.impossibleByInvariant("only managed bootstrap service classes have service owners"),
    };
}

fn serviceId(state: *const support.BootstrapState, class: contract.ServiceClass) u64 {
    return switch (class) {
        .service_registry => state.services.service_registry.id,
        .policy_mediation => state.services.policy_service.id,
        .permission_review_ui => state.services.review_service_record.id,
        .network_stack => state.services.network_service.id,
        .storage_object => state.services.storage_service.id,
        .package_install_update => state.services.package_service.id,
        .compositor_ui_session => state.services.compositor_service.id,
        .indexing_search => state.services.indexing_service.id,
        .sync_replication => state.services.sync_service.id,
        .media_print_helpers => state.services.media_service.id,
        .compatibility_portal => state.services.compatibility_service.id,
        else => native_util.impossibleByInvariant("only managed bootstrap service classes have service ids"),
    };
}

fn bootFailureCode(err: anyerror) u32 {
    var hash: u64 = 14695981039346656037;
    for (@errorName(err)) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    return @truncate(hash);
}
