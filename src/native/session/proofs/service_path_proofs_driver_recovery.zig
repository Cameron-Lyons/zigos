const std = @import("std");
const bootstrap_driver_port = @import("../../drivers/bootstrap_driver_port.zig");
const capability = @import("../../kernel_api/capability.zig");
const driver_runtime_mod = @import("../../drivers/driver_runtime.zig");
const driver_service = @import("../../drivers/driver_service.zig");
const notification_center = @import("../../services/notification_center.zig");
const session_manager = @import("../session_manager.zig");
const service_catalog = @import("../service_catalog.zig");
const storage_volume = @import("../../storage/storage_volume.zig");
const supervisor_mod = @import("../supervisor.zig");
const task_runtime = @import("../../task/task_runtime.zig");

const storage_restart_probe_lba: u64 = storage_volume.required_device_sectors + 32;
const storage_restart_probe_sectors: u64 = 4;
const storage_restart_probe_image_bytes: usize = @as(usize, @intCast(storage_restart_probe_lba + storage_restart_probe_sectors)) * storage_volume.sector_size;

const PublishedStorageBackend = struct {
    var target_device_id: u64 = 0;
    var image: []u8 = &.{};

    fn reset(image_buffer: []u8, device_id: u64) void {
        @memset(image_buffer, 0);
        image = image_buffer;
        target_device_id = device_id;
    }

    fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
        const buffer = buffer_ptr[0..buffer_len];
        const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
        const end = start + buffer.len;
        if (end > image.len) return false;
        @memcpy(buffer, image[start..end]);
        return true;
    }

    fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
        if (buffer_len % storage_volume.sector_size != 0) return false;
        const buffer = buffer_ptr[0..buffer_len];
        const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
        const end = start + buffer.len;
        if (end > image.len) return false;
        @memcpy(image[start..end], buffer);
        return true;
    }

    fn activate(device_id: u64) ?storage_volume.Backend {
        if (device_id != target_device_id) return null;
        return .{
            .sector_count = storage_restart_probe_lba + storage_restart_probe_sectors,
            .read = read,
            .write = write,
        };
    }
};

pub fn proveBootedDriverHotSwapAndRecoveryRebindLiveBrokeredDeviceAuthority() !void {
    const BootedDriverRuntime = struct {
        tasks: *task_runtime.Runtime,
        activations: *driver_runtime_mod.Runtime,
        rehost_count: usize = 0,
        deactivation_count: usize = 0,
        activation_count: usize = 0,
        last_task_id: u64 = 0,
        last_process_generation: u32 = 0,
        last_dma_domain_id: u64 = 0,

        pub fn deactivate(self: *@This(), service_id: u64) bool {
            const deactivated = self.activations.deactivate(service_id);
            if (deactivated) self.deactivation_count += 1;
            return deactivated;
        }

        pub fn deactivateDriver(self: *@This(), service_id: u64, device_class: driver_service.DeviceClass) bool {
            const deactivated = self.activations.deactivateDriver(service_id, device_class);
            if (deactivated) self.deactivation_count += 1;
            return deactivated;
        }

        pub fn activateAt(self: *@This(), driver: *const driver_service.DriverRecord, tick: u64) !driver_runtime_mod.ActivationRecord {
            const task = self.tasks.find(driver.owner_task_id) orelse return error.TaskNotFound;
            const previous_generation = task.process_generation;
            const rehosted = try self.tasks.rehostTask(driver.owner_task_id, tick);
            const restarted_task = self.tasks.find(driver.owner_task_id) orelse return error.TaskNotFound;
            const activation = try self.activations.activateAt(driver, tick);
            self.activation_count += 1;
            self.last_task_id = driver.owner_task_id;
            self.last_process_generation = restarted_task.process_generation;
            self.last_dma_domain_id = activation.dma_domain_id;
            if (rehosted and restarted_task.process_generation > previous_generation) {
                self.rehost_count += 1;
            }
            return activation;
        }

        pub fn revokeCapability(self: *@This(), task_id: u64, capability_id: u64) !bool {
            return self.tasks.revokeCapability(task_id, capability_id);
        }
    };

    bootstrap_driver_port.reset();
    defer bootstrap_driver_port.reset();
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    const runtime = session_manager.testing.runtimePtr();
    const capability_table = session_manager.system().capabilityTablePtr();
    const supervisor = session_manager.testing.supervisorPtr();
    const driver_directory = session_manager.testing.driverDirectoryPtr();
    const driver_runtime = session_manager.testing.driverRuntimePtr();
    const ledger = session_manager.testing.updateLedgerPtr();

    const storage_service_record = supervisor.findByClass(.storage_object).?;
    const network_service = supervisor.findByClass(.network_stack).?;
    const session_task = session_manager.testing.findTask("session-manager").?;
    const network_task = session_manager.testing.findTask("network-service").?;
    const storage_driver = driver_directory.findByClass(.storage_controller).?;
    const storage_driver_task = runtime.find(storage_driver.owner_task_id).?;

    const service_count_before = session_manager.testing.countServices();
    const task_count_before = session_manager.testing.countTasks();
    const session_process_generation_before = session_task.process_generation;
    const network_restart_count_before = network_service.restart_count;
    const network_process_generation_before = network_task.process_generation;
    const storage_restart_count_before = storage_service_record.restart_count;
    const storage_restart_generation_before = storage_driver.restart_generation;
    const storage_dma_before = storage_driver.dma_domain_id;
    const storage_process_generation_before = storage_driver_task.process_generation;
    const storage_address_space_before = storage_driver_task.address_space_id;

    bootstrap_driver_port.reset();
    var storage_image = [_]u8{0} ** storage_restart_probe_image_bytes;
    PublishedStorageBackend.reset(storage_image[0..], storage_driver.device_id);
    try std.testing.expect(try bootstrap_driver_port.publishStorageActivator(
        storage_driver.device_id,
        "zigos.system.storage-driver",
        PublishedStorageBackend.activate,
        false,
    ));

    const initial_activation = try driver_runtime.activateAt(storage_driver, 780);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, initial_activation.mode);
    try std.testing.expect(initial_activation.exclusive_claim);
    try std.testing.expect(initial_activation.iommu_enforced);

    runtime.allowHostPointerSyscallsForTask(storage_driver.owner_task_id);
    try provePublishedStorageWriteRead(storage_service_record.id, storage_restart_probe_lba, "driver-restart-before", 0x31);

    var booted_runtime = BootedDriverRuntime{
        .tasks = runtime,
        .activations = driver_runtime,
    };

    const recovery = try supervisor.recoverDriverCrash(
        storage_service_record.id,
        driver_directory,
        &booted_runtime,
        null,
        ledger,
        790,
        0x510,
        "storage driver brokered crash",
    );

    const recovered_driver = driver_directory.findByClass(.storage_controller).?;
    const recovered_task = runtime.find(recovered_driver.owner_task_id).?;
    try std.testing.expect(!recovery.visible_impact);
    try std.testing.expect(recovery.notification_id == null);
    try std.testing.expect(recovery.runtime_activation_observed);
    try std.testing.expect(recovery.runtime_activation_generation > initial_activation.activation_generation);
    try std.testing.expectEqual(recovered_driver.dma_domain_id, recovery.runtime_dma_domain_id);
    try std.testing.expect(recovery.runtime_exclusive_claim);
    try std.testing.expect(recovery.published_data_plane);
    try std.testing.expectEqual(@as(usize, 1), booted_runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 1), booted_runtime.activation_count);
    try std.testing.expectEqual(@as(usize, 1), booted_runtime.rehost_count);
    try std.testing.expectEqual(recovered_driver.owner_task_id, booted_runtime.last_task_id);
    try std.testing.expectEqual(recovered_task.process_generation, booted_runtime.last_process_generation);
    try std.testing.expectEqual(recovered_driver.dma_domain_id, booted_runtime.last_dma_domain_id);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, storage_service_record.state);
    try std.testing.expectEqual(storage_restart_count_before + 1, storage_service_record.restart_count);
    try std.testing.expectEqual(storage_restart_generation_before + 1, recovered_driver.restart_generation);
    try std.testing.expect(recovered_driver.dma_domain_id != storage_dma_before);
    try std.testing.expectEqual(storage_process_generation_before + 1, recovered_task.process_generation);
    try std.testing.expect(runtime.findAddressSpaceConst(storage_address_space_before) == null);
    try std.testing.expect(supervisor.hasDiagnostic(storage_service_record.id, .crash));
    try std.testing.expect(supervisor.hasDiagnostic(storage_service_record.id, .restart_completed));
    try std.testing.expectEqual(service_catalog.ServiceClass.storage_object, ledger.latestKind(.process_crash).?.service_class);
    try std.testing.expectEqual(recovered_driver.authority_capability_id, ledger.latestKind(.driver_restart).?.related_id);
    try std.testing.expectEqual(network_restart_count_before, network_service.restart_count);
    try std.testing.expectEqual(network_process_generation_before, network_task.process_generation);
    try std.testing.expect(session_manager.testing.isInitialized());
    try std.testing.expectEqual(service_count_before, session_manager.testing.countServices());
    try std.testing.expectEqual(task_count_before, session_manager.testing.countTasks());
    try std.testing.expectEqual(session_process_generation_before, session_task.process_generation);

    runtime.allowHostPointerSyscallsForTask(recovered_driver.owner_task_id);
    try provePublishedStorageReadback(storage_service_record.id, storage_restart_probe_lba, "driver-restart-before", 0x31);
    try provePublishedStorageRebound(storage_service_record.id, recovered_driver);
    try provePublishedStorageWriteRead(storage_service_record.id, storage_restart_probe_lba + 1, "driver-restart-after-crash", 0x52);

    const recovered_authority_id = recovered_driver.authority_capability_id;
    const hot_swap_process_generation_before = recovered_task.process_generation;
    const hot_swap_address_space_before = recovered_task.address_space_id;
    const hot_swap_restart_generation_before = recovered_driver.restart_generation;
    const hot_swap_dma_before = recovered_driver.dma_domain_id;
    const next_authority = try driver_service.mintDriverAuthority(capability_table, .{
        .holder = storage_service_record.owner,
        .task_id = recovered_driver.owner_task_id,
        .device_id = recovered_driver.device_id,
        .device_class = .storage_controller,
        .issued_at_ticks = 800,
        .renewable = false,
        .audit = .{
            .policy_generation = 1,
            .source_task_id = session_task.id,
            .broker_service_id = storage_service_record.id,
        },
    });
    try runtime.grantCapability(recovered_driver.owner_task_id, next_authority.id);

    const hot_swap = try supervisor.hotSwapDriver(.{
        .service_id = storage_service_record.id,
        .owner_task_id = recovered_driver.owner_task_id,
        .device_id = recovered_driver.device_id,
        .device_class = .storage_controller,
        .authority_capability_id = next_authority.id,
        .capability_table = capability_table,
        .requester = storage_service_record.owner,
        .now_ticks = 800,
        .signer = "zigos-storage-driver-v2",
        .bootstrap_transport = .kernel_bootstrap_broker,
    }, driver_directory, &booted_runtime, null, ledger, 800, "storage driver hot-swapped through broker");

    const swapped_driver = driver_directory.findByClass(.storage_controller).?;
    const swapped_task = runtime.find(swapped_driver.owner_task_id).?;
    try std.testing.expect(!hot_swap.visible_impact);
    try std.testing.expect(hot_swap.notification_id == null);
    try std.testing.expectEqual(hot_swap_restart_generation_before, hot_swap.previous_restart_generation);
    try std.testing.expectEqual(hot_swap_restart_generation_before + 1, hot_swap.next_restart_generation);
    try std.testing.expectEqual(hot_swap_dma_before, hot_swap.previous_dma_domain_id);
    try std.testing.expect(swapped_driver.dma_domain_id != hot_swap_dma_before);
    try std.testing.expectEqual(swapped_driver.dma_domain_id, hot_swap.next_dma_domain_id);
    try std.testing.expect(hot_swap.runtime_activation_observed);
    try std.testing.expect(hot_swap.runtime_activation_generation > recovery.runtime_activation_generation);
    try std.testing.expectEqual(swapped_driver.dma_domain_id, hot_swap.runtime_dma_domain_id);
    try std.testing.expect(hot_swap.runtime_exclusive_claim);
    try std.testing.expect(hot_swap.published_data_plane);
    try std.testing.expectEqual(next_authority.id, swapped_driver.authority_capability_id);
    try std.testing.expect(swapped_driver.authority_capability_id != recovered_authority_id);
    try std.testing.expectEqualStrings("zigos-storage-driver-v2", swapped_driver.signerSlice());
    try std.testing.expect(runtime.hasCapability(swapped_driver.owner_task_id, next_authority.id));
    try std.testing.expectEqual(hot_swap_process_generation_before + 1, swapped_task.process_generation);
    try std.testing.expect(runtime.findAddressSpaceConst(hot_swap_address_space_before) == null);
    try std.testing.expectEqual(@as(usize, 2), booted_runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 2), booted_runtime.activation_count);
    try std.testing.expectEqual(@as(usize, 2), booted_runtime.rehost_count);
    try std.testing.expectEqual(swapped_driver.owner_task_id, booted_runtime.last_task_id);
    try std.testing.expectEqual(swapped_task.process_generation, booted_runtime.last_process_generation);
    try std.testing.expectEqual(swapped_driver.dma_domain_id, booted_runtime.last_dma_domain_id);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, storage_service_record.state);
    try std.testing.expectEqual(storage_restart_count_before + 2, storage_service_record.restart_count);
    try std.testing.expect(supervisor.hasDiagnostic(storage_service_record.id, .driver_attached));
    try std.testing.expect(supervisor.hasDiagnostic(storage_service_record.id, .restart_completed));
    try std.testing.expectEqual(next_authority.id, ledger.latestKind(.driver_restart).?.related_id);
    try std.testing.expectEqual(network_restart_count_before, network_service.restart_count);
    try std.testing.expectEqual(network_process_generation_before, network_task.process_generation);
    try std.testing.expectEqual(service_count_before, session_manager.testing.countServices());
    try std.testing.expectEqual(task_count_before, session_manager.testing.countTasks());
    try std.testing.expectEqual(session_process_generation_before, session_task.process_generation);
    try std.testing.expect(!runtime.hasCapability(swapped_driver.owner_task_id, recovered_authority_id));

    runtime.allowHostPointerSyscallsForTask(swapped_driver.owner_task_id);
    try provePublishedStorageRebound(storage_service_record.id, swapped_driver);
    try provePublishedStorageReadback(storage_service_record.id, storage_restart_probe_lba + 1, "driver-restart-after-crash", 0x52);
    try provePublishedStorageWriteRead(storage_service_record.id, storage_restart_probe_lba + 2, "driver-restart-after-swap", 0x73);

    const compositor_service_record = supervisor.findByClass(.compositor_ui_session).?;
    const graphics_driver = driver_directory.findByClass(.graphics_adapter).?;
    const input_driver = driver_directory.findByClass(.input_device).?;
    try std.testing.expect(try bootstrap_driver_port.publishDeviceDataPlane(
        .graphics_adapter,
        graphics_driver.device_id,
        "zigos.system.compositor",
        false,
    ));
    try std.testing.expect(try bootstrap_driver_port.publishDeviceDataPlane(
        .input_device,
        input_driver.device_id,
        "zigos.system.compositor",
        false,
    ));
    const graphics_reactivation = try driver_runtime.activateAt(graphics_driver, 818);
    const input_reactivation = try driver_runtime.activateAt(input_driver, 819);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, graphics_reactivation.mode);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, input_reactivation.mode);
    const graphics_task = runtime.find(graphics_driver.owner_task_id).?;
    const input_activation_before = driver_runtime.findByClass(.input_device) orelse return error.MissingBootedDriverBinding;
    const graphics_restart_count_before = compositor_service_record.restart_count;
    const graphics_restart_generation_before = graphics_driver.restart_generation;
    const graphics_dma_before = graphics_driver.dma_domain_id;
    const graphics_process_generation_before = graphics_task.process_generation;
    const graphics_address_space_before = graphics_task.address_space_id;
    const graphics_authority = try driver_service.mintDriverAuthority(capability_table, .{
        .holder = compositor_service_record.owner,
        .task_id = graphics_driver.owner_task_id,
        .device_id = graphics_driver.device_id,
        .device_class = .graphics_adapter,
        .issued_at_ticks = 820,
        .renewable = false,
        .audit = .{
            .policy_generation = 2,
            .source_task_id = session_task.id,
            .broker_service_id = compositor_service_record.id,
        },
    });
    try runtime.grantCapability(graphics_driver.owner_task_id, graphics_authority.id);

    var notifications = notification_center.Center.init();
    const graphics_hot_swap = try supervisor.hotSwapDriver(.{
        .service_id = compositor_service_record.id,
        .owner_task_id = graphics_driver.owner_task_id,
        .device_id = graphics_driver.device_id,
        .device_class = .graphics_adapter,
        .authority_capability_id = graphics_authority.id,
        .capability_table = capability_table,
        .requester = compositor_service_record.owner,
        .now_ticks = 820,
        .signer = "zigos-graphics-driver-v2",
    }, driver_directory, &booted_runtime, &notifications, ledger, 820, "graphics driver hot-swapped through compositor service");

    const swapped_graphics = driver_directory.findByClass(.graphics_adapter).?;
    const swapped_graphics_task = runtime.find(swapped_graphics.owner_task_id).?;
    const input_activation_after = driver_runtime.findByClass(.input_device) orelse return error.MissingBootedDriverBinding;
    try std.testing.expect(graphics_hot_swap.visible_impact);
    try std.testing.expect(graphics_hot_swap.notification_id != null);
    try std.testing.expectEqual(notification_center.Reason.driver_restart, notifications.latestVisible(821).?.reason);
    try std.testing.expectEqual(graphics_restart_generation_before, graphics_hot_swap.previous_restart_generation);
    try std.testing.expectEqual(graphics_restart_generation_before + 1, graphics_hot_swap.next_restart_generation);
    try std.testing.expectEqual(graphics_dma_before, graphics_hot_swap.previous_dma_domain_id);
    try std.testing.expect(swapped_graphics.dma_domain_id != graphics_dma_before);
    try std.testing.expectEqual(swapped_graphics.dma_domain_id, graphics_hot_swap.next_dma_domain_id);
    try std.testing.expect(graphics_hot_swap.runtime_activation_observed);
    try std.testing.expectEqual(swapped_graphics.dma_domain_id, graphics_hot_swap.runtime_dma_domain_id);
    try std.testing.expect(graphics_hot_swap.runtime_exclusive_claim);
    try std.testing.expect(graphics_hot_swap.published_data_plane);
    try std.testing.expectEqual(graphics_authority.id, swapped_graphics.authority_capability_id);
    try std.testing.expectEqualStrings("zigos-graphics-driver-v2", swapped_graphics.signerSlice());
    try std.testing.expect(runtime.hasCapability(swapped_graphics.owner_task_id, graphics_authority.id));
    try std.testing.expectEqual(graphics_process_generation_before + 1, swapped_graphics_task.process_generation);
    try std.testing.expect(runtime.findAddressSpaceConst(graphics_address_space_before) == null);
    try std.testing.expectEqual(@as(usize, 3), booted_runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 3), booted_runtime.activation_count);
    try std.testing.expectEqual(@as(usize, 3), booted_runtime.rehost_count);
    try std.testing.expectEqual(swapped_graphics.owner_task_id, booted_runtime.last_task_id);
    try std.testing.expectEqual(swapped_graphics_task.process_generation, booted_runtime.last_process_generation);
    try std.testing.expectEqual(swapped_graphics.dma_domain_id, booted_runtime.last_dma_domain_id);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, compositor_service_record.state);
    try std.testing.expectEqual(graphics_restart_count_before + 1, compositor_service_record.restart_count);
    try std.testing.expect(supervisor.hasDiagnostic(compositor_service_record.id, .driver_attached));
    try std.testing.expect(supervisor.hasDiagnostic(compositor_service_record.id, .restart_completed));
    try std.testing.expectEqual(graphics_authority.id, ledger.latestKind(.driver_restart).?.related_id);
    try std.testing.expectEqual(input_driver.service_id, compositor_service_record.id);
    try std.testing.expectEqual(input_activation_before.activation_generation, input_activation_after.activation_generation);
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, input_activation_after.mode);
    try std.testing.expect(input_activation_after.exclusive_claim);
    try std.testing.expectEqual(compositor_service_record.id, bootstrap_driver_port.deviceDataPlanePublication(.input_device).?.active_service_id);
    try std.testing.expectEqual(network_restart_count_before, network_service.restart_count);
    try std.testing.expectEqual(network_process_generation_before, network_task.process_generation);
    try std.testing.expectEqual(storage_restart_count_before + 2, storage_service_record.restart_count);
    try std.testing.expectEqual(service_count_before, session_manager.testing.countServices());
    try std.testing.expectEqual(task_count_before, session_manager.testing.countTasks());
    try std.testing.expectEqual(session_process_generation_before, session_task.process_generation);
}

fn provePublishedStorageWriteRead(service_id: u64, lba: u64, label: []const u8, salt: u8) !void {
    var expected: [storage_volume.sector_size]u8 = undefined;
    fillStoragePattern(expected[0..], label, salt);
    try std.testing.expect(bootstrap_driver_port.activeStorageWrite(service_id, lba, expected[0..]));
    try provePublishedStorageReadback(service_id, lba, label, salt);
}

fn provePublishedStorageReadback(service_id: u64, lba: u64, label: []const u8, salt: u8) !void {
    var expected: [storage_volume.sector_size]u8 = undefined;
    var readback: [storage_volume.sector_size]u8 = undefined;
    fillStoragePattern(expected[0..], label, salt);
    @memset(readback[0..], 0);
    try std.testing.expect(bootstrap_driver_port.activeStorageRead(service_id, lba, readback[0..]));
    try std.testing.expect(std.mem.eql(u8, expected[0..], readback[0..]));
}

fn provePublishedStorageRebound(service_id: u64, driver: *const driver_service.DriverRecord) !void {
    try std.testing.expect(driver.dma_domain_id != 0);
    try std.testing.expect(storage_volume.hasProductionStorageBackend());
    var readback: [storage_volume.sector_size]u8 = undefined;
    @memset(readback[0..], 0);
    try std.testing.expect(bootstrap_driver_port.activeStorageRead(service_id, storage_restart_probe_lba, readback[0..]));
}

fn fillStoragePattern(buffer: []u8, label: []const u8, salt: u8) void {
    for (buffer, 0..) |*byte, index| {
        byte.* = @as(u8, @truncate((index * 17) + salt));
    }
    const label_len = @min(buffer.len, label.len);
    @memcpy(buffer[0..label_len], label[0..label_len]);
}
