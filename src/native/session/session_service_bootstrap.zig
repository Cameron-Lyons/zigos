const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const bootstrap_capabilities = @import("bootstrap_capabilities.zig");
const component_port = @import("../kernel_api/component_port.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const device_inventory = @import("../drivers/device_inventory.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const storage_driver_task_mod = @import("../drivers/storage_driver_task.zig");
const native_util = @import("../core/util.zig");
const std = @import("std");
const service_bootstrap = @import("service_bootstrap.zig");
const service_contract = @import("service_contracts.zig");
const root = @import("root");
const storage_volume_mod = if (builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume"))
    root.storage_volume
else
    @import("../storage/storage_volume.zig");
const support = @import("session_manager_support.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_launch = @import("../task/userspace_launch.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const storage_restart_scratch_lba: u64 = storage_volume_mod.required_device_sectors + 16;
const storage_restart_probe_sectors: u64 = 2;
const booted_storage_sector_count: u64 = storage_restart_scratch_lba + storage_restart_probe_sectors;
const booted_storage_image_bytes: usize = @as(usize, @intCast(booted_storage_sector_count)) * storage_volume_mod.sector_size;

const BootedNetworkDataPlane = struct {
    fn send(_: []const u8) void {}

    fn getMacAddress() [6]u8 {
        return .{ 0x02, 0x5A, 0x47, 0x00, 0x00, 0x01 };
    }

    const device = bootstrap_driver_port.NetworkDevice{
        .send = send,
        .getMacAddress = getMacAddress,
    };

    fn activate(device_id: u64) ?*const bootstrap_driver_port.NetworkDevice {
        if (device_id != device_inventory.deviceIdForClass(.network_adapter)) return null;
        return &device;
    }
};

const BootedStorageDataPlane = struct {
    var image = [_]u8{0} ** booted_storage_image_bytes;

    fn reset() void {
        @memset(image[0..], 0);
    }

    fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
        const buffer = buffer_ptr[0..buffer_len];
        const start = @as(usize, @intCast(start_lba)) * storage_volume_mod.sector_size;
        const end = start + buffer.len;
        if (end > image.len) return false;
        @memcpy(buffer, image[start..end]);
        return true;
    }

    fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
        const buffer = buffer_ptr[0..buffer_len];
        const start = @as(usize, @intCast(start_lba)) * storage_volume_mod.sector_size;
        const end = start + buffer.len;
        if (end > image.len) return false;
        @memcpy(image[start..end], buffer);
        return true;
    }

    fn activate(device_id: u64) ?storage_volume_mod.Backend {
        if (device_id != device_inventory.deviceIdForClass(.storage_controller)) return null;
        return .{
            .sector_count = booted_storage_sector_count,
            .read = read,
            .write = write,
        };
    }
};

const StorageRestartProbe = struct {
    old_session: ?storage_driver_task_mod.AtaControllerSession = null,
    stale_access_rejected: bool = false,

    fn verifyBeforeRestart(self: *@This(), service_id: u64) bool {
        var expected: [storage_volume_mod.sector_size]u8 = undefined;
        var readback: [storage_volume_mod.sector_size]u8 = undefined;
        fillPattern(expected[0..], "zigos-storage-before-restart", 0x21);
        @memset(readback[0..], 0);

        if (!bootstrap_driver_port.activeStorageWrite(service_id, storage_restart_scratch_lba, expected[0..])) return false;
        if (!bootstrap_driver_port.activeStorageRead(service_id, storage_restart_scratch_lba, readback[0..])) return false;
        if (!std.mem.eql(u8, expected[0..], readback[0..])) return false;

        self.old_session = bootstrap_driver_port.activeStorageAtaSession(service_id);
        if (builtin.target.os.tag == .freestanding and self.old_session == null) return false;
        return true;
    }

    fn rejectStaleAccessAfterGenerationChange(self: *@This()) bool {
        var session = self.old_session orelse {
            self.stale_access_rejected = builtin.target.os.tag != .freestanding;
            return self.stale_access_rejected;
        };
        var stale_read: [storage_volume_mod.sector_size]u8 = undefined;
        self.stale_access_rejected = !storage_driver_task_mod.readAtaBootstrapSession(&session, storage_restart_scratch_lba, stale_read[0..]);
        return self.stale_access_rejected;
    }

    fn verifyAfterRestart(_: *@This(), service_id: u64) bool {
        var before_expected: [storage_volume_mod.sector_size]u8 = undefined;
        var after_expected: [storage_volume_mod.sector_size]u8 = undefined;
        var readback: [storage_volume_mod.sector_size]u8 = undefined;
        fillPattern(before_expected[0..], "zigos-storage-before-restart", 0x21);
        fillPattern(after_expected[0..], "zigos-storage-after-restart", 0x4B);
        @memset(readback[0..], 0);

        if (!bootstrap_driver_port.activeStorageRead(service_id, storage_restart_scratch_lba, readback[0..])) return false;
        if (!std.mem.eql(u8, before_expected[0..], readback[0..])) return false;

        @memset(readback[0..], 0);
        if (!bootstrap_driver_port.activeStorageWrite(service_id, storage_restart_scratch_lba + 1, after_expected[0..])) return false;
        if (!bootstrap_driver_port.activeStorageRead(service_id, storage_restart_scratch_lba + 1, readback[0..])) return false;
        return std.mem.eql(u8, after_expected[0..], readback[0..]);
    }

    fn fillPattern(buffer: []u8, label: []const u8, salt: u8) void {
        for (buffer, 0..) |*byte, index| {
            byte.* = @as(u8, @truncate((index * 31) + salt));
        }
        const label_len = @min(buffer.len, label.len);
        @memcpy(buffer[0..label_len], label[0..label_len]);
    }
};

const DriverRecoveryRuntime = struct {
    tasks: *task_runtime.Runtime,
    activations: *driver_runtime_mod.Runtime,
    rehost_count: usize = 0,
    deactivation_count: usize = 0,
    activation_count: usize = 0,
    last_task_id: u64 = 0,
    last_process_generation: u32 = 0,
    storage_probe: ?*StorageRestartProbe = null,

    pub fn deactivate(self: *@This(), service_id: u64) bool {
        const deactivated = self.activations.deactivate(service_id);
        if (deactivated) self.deactivation_count += 1;
        return deactivated;
    }

    pub fn activateAt(self: *@This(), driver: *const driver_service.DriverRecord, tick: u64) !driver_runtime_mod.ActivationRecord {
        const task = self.tasks.find(driver.owner_task_id) orelse return error.TaskNotFound;
        const previous_generation = task.process_generation;
        const rehosted = try self.tasks.rehostTask(driver.owner_task_id, tick);
        const restarted_task = self.tasks.find(driver.owner_task_id) orelse return error.TaskNotFound;
        if (driver.device_class == .storage_controller) {
            if (self.storage_probe) |probe| {
                if (!probe.rejectStaleAccessAfterGenerationChange()) return error.StaleStorageAccessNotRejected;
            }
        }
        const activation = try self.activations.activateAt(driver, tick);
        self.activation_count += 1;
        self.last_task_id = driver.owner_task_id;
        self.last_process_generation = restarted_task.process_generation;
        if (rehosted and restarted_task.process_generation > previous_generation) {
            self.rehost_count += 1;
        }
        return activation;
    }
};

pub fn resetBootedDataPlanes() void {
    BootedStorageDataPlane.reset();
}

pub fn run(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *support.ServiceBindings,
) bool {
    if (!bootServices(env, state, kernel_port, service_bindings)) return false;
    if (!connectClient(env, state, kernel_port, service_bindings)) return false;
    return proveDriverCrashRestart(env, state, service_bindings);
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
        _ = env.supervisor.recordCrash(support.serviceId(state, entry.class), entry.boot_tick, bootFailureCode(err));
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
            _ = env.supervisor.recordCrash(support.serviceId(state, entry.class), entry.boot_tick, bootFailureCode(err));
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
    return service_bootstrap.launchContractService(.{
        .catalog = env.userspace_catalog,
        .kernel_port = kernel_port,
        .service_directory = env.service_directory,
        .supervisor = env.supervisor,
        .authority_capability_id = state.session_capability.id,
        .controller_task_id = if (entry.class == .service_registry) state.session_task.id else 0,
        .schedule_task = env.userspace_scheduler,
        .owner = support.serviceOwner(state, entry.class),
        .service_id = support.serviceId(state, entry.class),
        .entry = entry,
    });
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
        .kernel_bootstrap_broker,
        "zigos.system.storage-driver",
        54,
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 54, bootFailureCode(err));
        return false;
    };
    const storage_inventory = device_inventory.recordForClass(.storage_controller);
    if (bootstrap_driver_port.storagePublication() == null and
        storage_inventory.detected and
        storage_inventory.source == .ata_bootstrap)
    {
        const claimed_storage_bootstrap = bootstrap_driver_port.claimStorageAtaBootstrapInventory(
            storage_driver,
            "zigos.system.storage-driver",
        ) catch false;
        if (!claimed_storage_bootstrap) {
            _ = env.supervisor.recordCrash(state.services.storage_service.id, 54, bootFailureCode(error.InvalidBootstrapTransport));
            return false;
        }
    }
    if (bootstrap_driver_port.storagePublication() == null) {
        const published_storage = bootstrap_driver_port.publishStorageActivator(
            storage_driver.device_id,
            "zigos.system.storage-driver",
            BootedStorageDataPlane.activate,
            false,
        ) catch false;
        if (!published_storage) {
            _ = env.supervisor.recordCrash(state.services.storage_service.id, 54, bootFailureCode(error.InvalidBootstrapTransport));
            return false;
        }
    }
    const graphics_driver = service_bootstrap.attachDriver(
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
    const input_driver = service_bootstrap.attachDriver(
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
        .input_device,
        .none,
        "zigos.system.compositor",
        57,
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.compositor_service.id, 57, bootFailureCode(err));
        return false;
    };
    const audio_driver = service_bootstrap.attachDriver(
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
        58,
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.media_service.id, 58, bootFailureCode(err));
        return false;
    };

    if (bootstrap_driver_port.networkPublication() == null) {
        const published_network = bootstrap_driver_port.publishNetworkActivator(
            network_driver.device_id,
            "zigos.system.network-stack",
            BootedNetworkDataPlane.activate,
            false,
        ) catch false;
        if (!published_network) {
            _ = env.supervisor.recordCrash(state.services.network_service.id, 53, bootFailureCode(error.InvalidBootstrapTransport));
            return false;
        }
    }
    if (!publishBootedDeviceDataPlane(env, state.services.compositor_service.id, graphics_driver, "zigos.system.compositor", 55)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.compositor_service.id, input_driver, "zigos.system.compositor", 57)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.media_service.id, audio_driver, "zigos.system.media-print", 58)) return false;

    const network_activation_mode = env.driver_runtime.activateModeAt(network_driver, 53) catch |err| {
        _ = env.supervisor.recordCrash(state.services.network_service.id, 53, bootFailureCode(err));
        return false;
    };
    const storage_activation_mode = env.driver_runtime.activateModeAt(storage_driver, 54) catch |err| {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 54, bootFailureCode(err));
        return false;
    };
    _ = env.driver_runtime.activateModeAt(graphics_driver, 55) catch |err| {
        _ = env.supervisor.recordCrash(state.services.compositor_service.id, 55, bootFailureCode(err));
        return false;
    };
    _ = env.driver_runtime.activateModeAt(input_driver, 57) catch |err| {
        _ = env.supervisor.recordCrash(state.services.compositor_service.id, 57, bootFailureCode(err));
        return false;
    };
    _ = env.driver_runtime.activateModeAt(audio_driver, 58) catch |err| {
        _ = env.supervisor.recordCrash(state.services.media_service.id, 58, bootFailureCode(err));
        return false;
    };
    if (network_activation_mode == .published_data_plane and
        (storage_activation_mode == .published_data_plane or
            storage_activation_mode == .userspace_brokered_data_plane))
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

fn publishBootedDeviceDataPlane(
    env: *const support.Environment,
    service_id: u64,
    driver: *const driver_service.DriverRecord,
    publisher: []const u8,
    tick: u64,
) bool {
    const published = bootstrap_driver_port.publishDeviceDataPlane(
        driver.device_class,
        driver.device_id,
        publisher,
        false,
    ) catch false;
    if (published) return true;

    _ = env.supervisor.recordCrash(service_id, tick, bootFailureCode(error.InvalidBootstrapTransport));
    return false;
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
            _ = env.supervisor.recordCrash(support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), bootFailureCode(err));
            return false;
        };
        const registry_connection = env.service_directory.connect(entry.interface) catch |err| {
            _ = env.supervisor.recordCrash(support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), bootFailureCode(err));
            return false;
        };
        _ = kernel_port.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, connect_request_id, service_client_task.id),
            .endpoint_capability_id = client_endpoint.capability_id,
            .peer_endpoint_capability_id = registry_connection.endpoint_capability_id,
            .peer_endpoint_id = binding.endpoint_id,
        }, 57 + @as(u64, @intCast(index))) catch |err| {
            _ = env.supervisor.recordCrash(support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), bootFailureCode(err));
            return false;
        };
        env.runtime.audit(service_client_task.id, .{
            .kind = .service_connected,
            .detail = @truncate(registry_connection.service_id),
            .tick = 57 + @as(u64, @intCast(index)),
        }) catch |err| {
            _ = env.supervisor.recordCrash(support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), bootFailureCode(err));
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

pub fn proveDriverCrashRestart(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    service_bindings: *const support.ServiceBindings,
) bool {
    var recovery_runtime = DriverRecoveryRuntime{
        .tasks = env.runtime,
        .activations = env.driver_runtime,
    };

    _ = env.supervisor.recoverDriverCrash(
        state.services.network_service.id,
        env.driver_directory,
        &recovery_runtime,
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
        common.printBootMarker(boot_markers.service_boot_supervisor_crash_recorded);
    }
    env.runtime.audit(service_bindings.bindingFor(.network_stack).task_id, .{
        .kind = .service_restarted,
        .detail = @truncate(state.services.network_service.id),
        .tick = 72,
    }) catch |err| {
        _ = env.supervisor.recordCrash(state.services.network_service.id, 72, bootFailureCode(err));
        return false;
    };
    if (recovery_runtime.rehost_count == 1 and
        recovery_runtime.deactivation_count == 1 and
        recovery_runtime.activation_count == 1 and
        recovery_runtime.last_process_generation >= 2)
    {
        common.printBootMarker(boot_markers.service_boot_driver_rehost_ok);
    } else {
        _ = env.supervisor.recordCrash(state.services.network_service.id, 72, bootFailureCode(error.MissingBootstrapLaunch));
        return false;
    }
    if (env.supervisor.hasDiagnostic(state.services.network_service.id, .restart_completed) and
        (env.driver_directory.findByService(state.services.network_service.id) orelse return false).restart_generation == 2)
    {
        common.printBootMarker(boot_markers.service_boot_supervisor_restart_ok);
        common.printBootMarker(boot_markers.service_boot_supervisor_restart_without_reboot);
    }

    return proveStorageDriverRestartIo(env, state);
}

pub fn proveStorageDriverRestartIo(
    env: *const support.Environment,
    state: *const support.BootstrapState,
) bool {
    var storage_probe = StorageRestartProbe{};
    if (!storage_probe.verifyBeforeRestart(state.services.storage_service.id)) {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 80, bootFailureCode(error.MissingBootstrapLaunch));
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_io_before_restart_ok);

    var recovery_runtime = DriverRecoveryRuntime{
        .tasks = env.runtime,
        .activations = env.driver_runtime,
        .storage_probe = &storage_probe,
    };
    const storage_recovery = env.supervisor.recoverDriverCrash(
        state.services.storage_service.id,
        env.driver_directory,
        &recovery_runtime,
        null,
        env.diagnostic_ledger,
        81,
        0x57,
        "storage driver restarted",
    ) catch |err| {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 81, bootFailureCode(err));
        return false;
    };

    const storage_driver = env.driver_directory.findByService(state.services.storage_service.id) orelse return false;
    const expected_storage_data_plane = storage_recovery.userspace_brokered_data_plane or builtin.target.os.tag != .freestanding;
    if (!storage_probe.stale_access_rejected or
        !storage_recovery.runtime_activation_observed or
        !storage_recovery.runtime_exclusive_claim or
        !expected_storage_data_plane or
        recovery_runtime.last_task_id != storage_driver.owner_task_id or
        recovery_runtime.last_process_generation < 2 or
        storage_driver.restart_generation != 2)
    {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 83, bootFailureCode(error.MissingBootstrapLaunch));
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_stale_access_rejected);

    if (!storage_probe.verifyAfterRestart(state.services.storage_service.id)) {
        _ = env.supervisor.recordCrash(state.services.storage_service.id, 84, bootFailureCode(error.MissingBootstrapLaunch));
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_io_after_restart_ok);
    return true;
}

fn bootFailureCode(err: anyerror) u32 {
    return @truncate(native_util.fnv1a64(@errorName(err)));
}
