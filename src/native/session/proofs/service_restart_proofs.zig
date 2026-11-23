//! Verification-kernel driver restart and service connection proofs. Only the
//! verification service graph and the hosted demo import this module.
const builtin = @import("builtin");
const std = @import("std");
const authorization_clock = @import("../authorization_clock.zig");
const boot_markers = @import("../../../kernel/boot/markers.zig");
const bootstrap_capabilities = @import("../bootstrap_capabilities.zig");
const bootstrap_driver_port = @import("../../drivers/bootstrap_driver_port.zig");
const component_port = @import("../../kernel_api/component_port.zig");
const device_broker = @import("../../kernel_api/device_broker.zig");
const driver_runtime_mod = @import("../../drivers/driver_runtime.zig");
const driver_service = @import("../../drivers/driver_service.zig");
const service_catalog = @import("../service_catalog.zig");
const session_service_bootstrap = @import("../session_service_bootstrap.zig");
const storage_volume_mod = @import("../../storage/storage_volume.zig");
const support = @import("../session_manager_support.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const units = @import("../../core/units.zig");
const userspace_launch = @import("../../task/userspace_launch.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const StorageRestartProbe = struct {
    old_controller_session: ?bootstrap_driver_port.StorageControllerSession = null,
    old_authority_capability_id: u64 = 0,
    old_process_generation: u32 = 0,
    old_dma_domain_id: u64 = 0,
    old_dma_domain_programmed: bool = false,
    old_brokered_dma_buffer_ready: bool = false,
    controller_fault_contained: bool = false,
    partial_transfer_rejected: bool = false,
    stale_authority_rejected: bool = false,
    stale_dma_access_rejected: bool = false,
    stale_access_rejected: bool = false,
    rebind_observed: bool = false,
    rebound_dma_domain_programmed: bool = false,
    rebound_brokered_dma_buffer_ready: bool = false,
    controller_revoke_rejected: bool = false,
    stale_broker_session_rejected: bool = false,
    republished_session_ready: bool = false,

    fn verifyBeforeRestart(self: *@This(), service_id: u64) bool {
        var expected: [storage_volume_mod.sector_size]u8 = undefined;
        var readback: [storage_volume_mod.sector_size]u8 = undefined;
        fillPattern(expected[0..], "zigos-storage-before-restart", 0x21);
        @memset(readback[0..], 0);

        if (!bootstrap_driver_port.activeStorageWrite(service_id, session_service_bootstrap.storage_restart_scratch_lba, expected[0..])) return false;
        if (!bootstrap_driver_port.activeStorageRead(service_id, session_service_bootstrap.storage_restart_scratch_lba, readback[0..])) return false;
        if (!std.mem.eql(u8, expected[0..], readback[0..])) return false;

        const session = bootstrap_driver_port.activeStorageControllerSession(service_id) orelse return false;
        self.old_controller_session = session;
        self.old_authority_capability_id = session.authority_capability_id;
        self.old_process_generation = session.process_generation;
        self.old_dma_domain_id = session.dma_domain_id;
        if (self.old_authority_capability_id == 0 or self.old_process_generation == 0 or self.old_dma_domain_id == 0) return false;
        self.old_dma_domain_programmed = session.dma_isolation.mode == .brokered_dma_buffers and
            session.dma_isolation.hardware_iommu_programmed and
            (builtin.target.os.tag != .freestanding or session.dma_isolation.bus_master_dma_enabled);
        self.old_brokered_dma_buffer_ready = device_broker.brokeredDmaBufferStillValid(session.brokered_dma_buffer);
        if (!self.old_dma_domain_programmed or !self.old_brokered_dma_buffer_ready) return false;
        return self.verifyModernDmaAndPartialTransfer(service_id, session, expected[0..]);
    }

    fn verifyModernDmaAndPartialTransfer(
        self: *@This(),
        service_id: u64,
        session: bootstrap_driver_port.StorageControllerSession,
        expected: []const u8,
    ) bool {
        const denied_address = std.math.maxInt(u64) - storage_volume_mod.sector_size;
        device_broker.validateDmaAccess(
            session.device_id,
            session.dma_domain_id,
            denied_address,
            storage_volume_mod.sector_size,
            .device_read,
        ) catch |err| {
            if (err != error.DmaWindowDenied) return false;
            self.controller_fault_contained = true;
        };
        if (!self.controller_fault_contained) return false;

        var partial_attempt: [storage_volume_mod.sector_size]u8 = undefined;
        fillPattern(partial_attempt[0..], "zigos-storage-partial-transfer", 0x67);
        self.partial_transfer_rejected = !bootstrap_driver_port.activeStorageWrite(
            service_id,
            session_service_bootstrap.storage_restart_scratch_lba,
            partial_attempt[0 .. storage_volume_mod.sector_size / 2],
        );
        if (!self.partial_transfer_rejected) return false;

        var readback: [storage_volume_mod.sector_size]u8 = undefined;
        @memset(readback[0..], 0);
        if (!bootstrap_driver_port.activeStorageRead(service_id, session_service_bootstrap.storage_restart_scratch_lba, readback[0..])) return false;
        return std.mem.eql(u8, expected, readback[0..]);
    }

    fn rejectStaleAccessAfterGenerationChange(self: *@This()) bool {
        const session = self.old_controller_session orelse return false;
        var stale_read: [storage_volume_mod.sector_size]u8 = undefined;
        self.stale_authority_rejected = !bootstrap_driver_port.storageSessionIsCurrent(&session);
        self.stale_dma_access_rejected = !device_broker.brokeredDmaBufferStillValid(session.brokered_dma_buffer);
        self.stale_access_rejected = !bootstrap_driver_port.activeStorageRead(
            session.service_id,
            session_service_bootstrap.storage_restart_scratch_lba,
            stale_read[0..],
        );
        return self.stale_authority_rejected and
            self.stale_dma_access_rejected and
            self.stale_access_rejected;
    }

    fn verifyReboundSession(self: *@This(), service_id: u64, driver: *const driver_service.DriverRecord) bool {
        const session = bootstrap_driver_port.activeStorageControllerSession(service_id) orelse return false;
        if (session.authority_capability_id != driver.authority_capability_id or
            session.task_id != driver.owner_task_id or
            session.process_generation <= self.old_process_generation or
            session.dma_domain_id != driver.dma_domain_id or
            session.dma_domain_id == self.old_dma_domain_id) return false;
        self.rebound_dma_domain_programmed = session.dma_isolation.mode == .brokered_dma_buffers and
            session.dma_isolation.hardware_iommu_programmed and
            (builtin.target.os.tag != .freestanding or session.dma_isolation.bus_master_dma_enabled);
        self.rebound_brokered_dma_buffer_ready = device_broker.brokeredDmaBufferStillValid(session.brokered_dma_buffer);
        self.rebind_observed = self.rebound_dma_domain_programmed and self.rebound_brokered_dma_buffer_ready;
        return self.rebind_observed;
    }

    fn verifyAfterRestart(_: *@This(), service_id: u64) bool {
        var before_expected: [storage_volume_mod.sector_size]u8 = undefined;
        var after_expected: [storage_volume_mod.sector_size]u8 = undefined;
        var readback: [storage_volume_mod.sector_size]u8 = undefined;
        fillPattern(before_expected[0..], "zigos-storage-before-restart", 0x21);
        fillPattern(after_expected[0..], "zigos-storage-after-restart", 0x4B);
        @memset(readback[0..], 0);

        if (!readRestartProbeStorage(service_id, session_service_bootstrap.storage_restart_scratch_lba, readback[0..])) return false;
        if (!std.mem.eql(u8, before_expected[0..], readback[0..])) return false;

        @memset(readback[0..], 0);
        if (!writeRestartProbeStorage(service_id, session_service_bootstrap.storage_restart_scratch_lba + 1, after_expected[0..])) return false;
        if (!readRestartProbeStorage(service_id, session_service_bootstrap.storage_restart_scratch_lba + 1, readback[0..])) return false;
        return std.mem.eql(u8, after_expected[0..], readback[0..]);
    }

    fn verifyBrokerRevocationRecovery(
        self: *@This(),
        service_id: u64,
        driver: *const driver_service.DriverRecord,
        kernel_port: *component_port.KernelPort,
    ) bool {
        const session = bootstrap_driver_port.activeStorageControllerSession(service_id) orelse return false;
        const broker_generation_before = session.broker_generation;
        var revoked_read: [storage_volume_mod.sector_size]u8 = undefined;
        if (!device_broker.revokePciController(session.device_id)) return false;
        self.controller_revoke_rejected = !bootstrap_driver_port.activeStorageRead(
            service_id,
            session_service_bootstrap.storage_restart_scratch_lba,
            revoked_read[0..],
        );
        if (!self.controller_revoke_rejected) return false;
        if (!device_broker.publishPciController(session.device_id)) return false;
        self.stale_broker_session_rejected = !bootstrap_driver_port.storageSessionIsCurrent(&session);
        if (!self.stale_broker_session_rejected) return false;

        if (!bootstrap_driver_port.deactivateStorageBackend(service_id)) return false;
        if (!bootstrap_driver_port.activateStorageBackend(
            driver.device_id,
            service_id,
            driver.authority_capability_id,
            driver.owner_task_id,
            driver.dma_domain_id,
            authorization_clock.at(86),
            kernel_port,
        )) return false;
        const republished_session = bootstrap_driver_port.activeStorageControllerSession(service_id) orelse return false;
        self.republished_session_ready = republished_session.broker_generation != broker_generation_before and
            republished_session.process_generation == session.process_generation and
            bootstrap_driver_port.storageSessionIsCurrent(&republished_session);
        return self.republished_session_ready;
    }

    fn readRestartProbeStorage(service_id: u64, start_lba: u64, buffer: []u8) bool {
        return bootstrap_driver_port.activeStorageRead(service_id, start_lba, buffer);
    }

    fn writeRestartProbeStorage(service_id: u64, start_lba: u64, buffer: []const u8) bool {
        return bootstrap_driver_port.activeStorageWrite(service_id, start_lba, buffer);
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

    pub fn deactivateDriver(self: *@This(), service_id: u64, device_class: driver_service.DeviceClass) bool {
        const deactivated = self.activations.deactivateDriver(service_id, device_class);
        if (deactivated) self.deactivation_count += 1;
        return deactivated;
    }

    pub fn activateAt(self: *@This(), driver: *const driver_service.DriverRecord, tick: u64) !driver_runtime_mod.ActivationRecord {
        const now_ticks = authorization_clock.at(tick);
        const task = self.tasks.find(driver.owner_task_id) orelse return error.TaskNotFound;
        const previous_generation = task.process_generation;
        const rehosted = try self.tasks.rehostTask(driver.owner_task_id, now_ticks);
        const restarted_task = self.tasks.find(driver.owner_task_id) orelse return error.TaskNotFound;
        if (driver.device_class == .storage_controller) {
            if (self.storage_probe) |probe| {
                if (!probe.rejectStaleAccessAfterGenerationChange()) return error.StaleStorageAccessNotRejected;
            }
        }
        const activation = try self.activations.activateAt(driver, now_ticks);
        self.activation_count += 1;
        self.last_task_id = driver.owner_task_id;
        self.last_process_generation = restarted_task.process_generation;
        if (rehosted and restarted_task.process_generation > previous_generation) {
            self.rehost_count += 1;
        }
        return activation;
    }
};

pub fn run(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *support.ServiceBindings,
) bool {
    if (!session_service_bootstrap.bootServices(env, state, kernel_port, service_bindings)) return false;
    if (!connectClient(env, state, kernel_port, service_bindings)) return false;
    return proveDriverCrashRestart(env, state, kernel_port, service_bindings);
}

pub fn connectClient(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *const support.ServiceBindings,
) bool {
    const service_client_task = userspace_launch.launchFromKernel(
        env.userspace_catalog,
        env.runtime,
        "zigos.system.service-client",
        .{
            .owner = .{ .kind = .app, .serial = 20 },
            .budget = .{
                .cpu_time_ticks = 6_000,
                .memory_bytes = units.kibibytes(512),
                // One endpoint per service plus one transient identity grant.
                .endpoint_slots = service_catalog.ordered_service_contracts.len + 1,
                .shared_memory_bytes = units.kibibytes(64),
                .background_allowed = false,
            },
            .local_only = true,
        },
        env.userspace_scheduler,
    ) catch |err| {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.service_registry).id, 56, err);
        return false;
    };
    const service_client_authority = env.capability_table.mintBootRoot(.{
        .holder = service_client_task.owner,
        .issuer = state.ids.policy_authority,
        .target = .{ .kind = .service, .id = state.services.get(.service_registry).id },
        .rights = bootstrap_capabilities.serviceBootstrapRights(),
        .scope = .{
            .task_id = service_client_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = authorization_clock.at(56),
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = false,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = 0,
            .broker_service_id = state.services.get(.service_registry).id,
        },
    }) catch |err| {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.service_registry).id, 56, err);
        return false;
    };
    task_runtime.grantCapabilityToTask(service_client_task, service_client_authority.id) catch |err| {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.service_registry).id, 56, err);
        return false;
    };

    var service_connect_count: usize = 0;
    for (service_catalog.ordered_service_contracts, service_bindings.bindings, 0..) |entry, binding, index| {
        const now_ticks = authorization_clock.at(57 + @as(u64, @intCast(index)));
        const client_endpoint = kernel_port.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, service_client_task.id),
            .authority_capability_id = service_client_authority.id,
            .owner_task_id = service_client_task.id,
            .label = entry.interface.name,
            .flags = .{ .local_only = true },
        }, now_ticks) catch |err| {
            session_service_bootstrap.recordBootFailure(env, support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), err);
            return false;
        };
        const registry_connection = env.service_directory.connect(entry.interface_id) catch |err| {
            session_service_bootstrap.recordBootFailure(env, support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), err);
            return false;
        };
        _ = kernel_port.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, service_client_task.id),
            .endpoint_capability_id = client_endpoint.capability_id,
            .peer_endpoint_capability_id = registry_connection.endpoint_capability_id,
            .peer_endpoint_id = binding.endpoint_id,
        }, now_ticks) catch |err| {
            session_service_bootstrap.recordBootFailure(env, support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), err);
            return false;
        };
        service_client_task.appendAudit(.{
            .kind = .service_connected,
            .detail = @truncate(registry_connection.service_id),
            .tick = 57 + @as(u64, @intCast(index)),
        });
        const service = env.supervisor.findByClass(entry.class) orelse return false;
        if (registry_connection.service_id == service.id) {
            service_connect_count += 1;
        }
    }
    if (service_connect_count == service_catalog.ordered_service_contracts.len) {
        common.printBootMarker(boot_markers.service_boot_ipc_connect_all_ok);
    }
    return true;
}

pub fn proveDriverCrashRestart(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *const support.ServiceBindings,
) bool {
    var recovery_runtime = DriverRecoveryRuntime{
        .tasks = env.runtime,
        .activations = env.driver_runtime,
    };

    _ = env.supervisor.recoverDriverCrash(
        state.services.get(.network_stack).id,
        env.driver_directory,
        &recovery_runtime,
        null,
        env.diagnostic_ledger,
        authorization_clock.at(70),
        0x4E,
        "network driver restarted",
    ) catch |err| {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.network_stack).id, 70, err);
        return false;
    };
    if (env.supervisor.hasDiagnostic(state.services.get(.network_stack).id, .crash)) {
        common.printBootMarker(boot_markers.service_boot_supervisor_crash_recorded);
    }
    env.runtime.audit(service_bindings.bindingFor(.network_stack).task_id, .{
        .kind = .service_restarted,
        .detail = @truncate(state.services.get(.network_stack).id),
        .tick = 72,
    }) catch |err| {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.network_stack).id, 72, err);
        return false;
    };
    if (recovery_runtime.rehost_count == 1 and
        recovery_runtime.deactivation_count == 1 and
        recovery_runtime.activation_count == 1 and
        recovery_runtime.last_process_generation >= 2)
    {
        common.printBootMarker(boot_markers.service_boot_driver_rehost_ok);
    } else {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.network_stack).id, 72, error.MissingBootstrapLaunch);
        return false;
    }
    if (env.supervisor.hasDiagnostic(state.services.get(.network_stack).id, .restart_completed) and
        (env.driver_directory.findByService(state.services.get(.network_stack).id) orelse return false).restart_generation == 2)
    {
        common.printBootMarker(boot_markers.service_boot_supervisor_restart_ok);
        common.printBootMarker(boot_markers.service_boot_supervisor_restart_without_reboot);
    }

    return proveStorageDriverRestartIo(env, state, kernel_port);
}

pub fn proveStorageDriverRestartIo(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
) bool {
    var storage_probe = StorageRestartProbe{};
    if (!storage_probe.verifyBeforeRestart(state.services.get(.storage_object).id)) {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.storage_object).id, 80, error.MissingBootstrapLaunch);
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_io_before_restart_ok);

    var recovery_runtime = DriverRecoveryRuntime{
        .tasks = env.runtime,
        .activations = env.driver_runtime,
        .storage_probe = &storage_probe,
    };
    const storage_recovery = env.supervisor.recoverDriverCrash(
        state.services.get(.storage_object).id,
        env.driver_directory,
        &recovery_runtime,
        null,
        env.diagnostic_ledger,
        authorization_clock.at(81),
        0x57,
        "storage driver restarted",
    ) catch |err| {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.storage_object).id, 81, err);
        return false;
    };

    const storage_driver = env.driver_directory.findByService(state.services.get(.storage_object).id) orelse return false;
    const expected_storage_data_plane = bootstrap_driver_port.activeStorageControllerSession(state.services.get(.storage_object).id) != null;
    if (!storage_probe.stale_authority_rejected or
        !storage_probe.stale_dma_access_rejected or
        !storage_probe.stale_access_rejected or
        !storage_probe.controller_fault_contained or
        !storage_probe.partial_transfer_rejected or
        !storage_probe.old_dma_domain_programmed or
        !storage_probe.old_brokered_dma_buffer_ready or
        !storage_recovery.runtime_exclusive_claim or
        !expected_storage_data_plane or
        recovery_runtime.last_task_id != storage_driver.owner_task_id or
        recovery_runtime.last_process_generation < 2 or
        storage_driver.restart_generation != 2)
    {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.storage_object).id, 83, error.MissingBootstrapLaunch);
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_dma_domain_programmed);
    common.printBootMarker(boot_markers.service_boot_storage_brokered_dma_buffer_ok);
    common.printBootMarker(boot_markers.service_boot_storage_controller_fault_contained);
    common.printBootMarker(boot_markers.service_boot_storage_partial_transfer_rejected);
    common.printBootMarker(boot_markers.service_boot_storage_stale_authority_rejected);
    common.printBootMarker(boot_markers.service_boot_storage_stale_dma_access_rejected);
    common.printBootMarker(boot_markers.service_boot_storage_stale_access_rejected);

    if (!storage_probe.verifyReboundSession(state.services.get(.storage_object).id, storage_driver) or
        !storage_probe.rebound_dma_domain_programmed or
        !storage_probe.rebound_brokered_dma_buffer_ready)
    {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.storage_object).id, 84, error.MissingBootstrapLaunch);
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_rebind_ok);

    if (!storage_probe.verifyBrokerRevocationRecovery(state.services.get(.storage_object).id, storage_driver, kernel_port) or
        !storage_probe.controller_revoke_rejected or
        !storage_probe.stale_broker_session_rejected or
        !storage_probe.republished_session_ready)
    {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.storage_object).id, 84, error.MissingBootstrapLaunch);
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_controller_revoke_rejected);
    common.printBootMarker(boot_markers.service_boot_storage_republish_after_revoke_ok);

    if (!storage_probe.verifyAfterRestart(state.services.get(.storage_object).id)) {
        session_service_bootstrap.recordBootFailure(env, state.services.get(.storage_object).id, 85, error.MissingBootstrapLaunch);
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_io_after_restart_ok);
    return true;
}
