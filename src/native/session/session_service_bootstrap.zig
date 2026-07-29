const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const bootstrap_capabilities = @import("bootstrap_capabilities.zig");
const component_port = @import("../kernel_api/component_port.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const accelerator_driver_task = @import("../drivers/accelerator_driver_task.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const device_inventory = @import("../drivers/device_inventory.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const std = @import("std");
const service_bootstrap = @import("service_bootstrap.zig");
const service_contract = @import("service_contracts.zig");
const units = @import("../core/units.zig");
const root = @import("root");
const storage_volume_mod = if (builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume"))
    root.storage_volume
else
    @import("../storage/storage_volume.zig");
const support = @import("session_manager_support.zig");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
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

const i225_bridge = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn zigosNetworkBootstrapI225Attached() callconv(.c) bool;
        extern fn zigosNetworkBootstrapI225Send(payload_ptr: [*]const u8, payload_len: usize) callconv(.c) bool;
        extern fn zigosNetworkBootstrapI225Receive(
            output_ptr: [*]u8,
            output_capacity: usize,
            output_len: *usize,
        ) callconv(.c) u8;
        extern fn zigosNetworkBootstrapI225Mac(output: [*]u8) callconv(.c) bool;

        pub fn attached() bool {
            return zigosNetworkBootstrapI225Attached();
        }

        pub fn send(payload: []const u8) bool {
            return zigosNetworkBootstrapI225Send(payload.ptr, payload.len);
        }

        pub fn receive(output: []u8) bootstrap_driver_port.ReceiveResult {
            var length: usize = 0;
            const status = zigosNetworkBootstrapI225Receive(output.ptr, output.len, &length);
            return .{
                .status = switch (status) {
                    0 => .empty,
                    1 => .frame,
                    2 => .dropped,
                    else => .failed,
                },
                .length = length,
            };
        }

        pub fn mac() ?[6]u8 {
            var address: [6]u8 = undefined;
            if (!zigosNetworkBootstrapI225Mac(&address)) return null;
            return address;
        }
    }
else
    struct {
        pub fn attached() bool {
            return false;
        }

        pub fn send(_: []const u8) bool {
            return false;
        }

        pub fn receive(_: []u8) bootstrap_driver_port.ReceiveResult {
            return .{ .status = .empty };
        }

        pub fn mac() ?[6]u8 {
            return null;
        }
    };

const BootedNetworkDataPlane = struct {
    fn send(data: []const u8) bool {
        if (i225_bridge.attached()) return i225_bridge.send(data);
        return builtin.target.os.tag != .freestanding or device_inventory.modelDeviceInventoryEnabled();
    }

    fn receive(output: []u8) bootstrap_driver_port.ReceiveResult {
        if (i225_bridge.attached()) return i225_bridge.receive(output);
        if (builtin.target.os.tag != .freestanding or device_inventory.modelDeviceInventoryEnabled()) {
            return .{ .status = .empty };
        }
        return .{ .status = .failed };
    }

    fn getMacAddress() [6]u8 {
        if (i225_bridge.mac()) |address| return address;
        return .{ 0x02, 0x5A, 0x47, 0x00, 0x00, 0x01 };
    }

    const device = bootstrap_driver_port.NetworkDevice{
        .send = send,
        .receive = receive,
        .getMacAddress = getMacAddress,
    };

    fn activate(device_id: u64) ?*const bootstrap_driver_port.NetworkDevice {
        if (device_id != device_inventory.deviceIdForClass(.network_adapter)) return null;
        if (builtin.target.os.tag == .freestanding and
            !i225_bridge.attached() and
            !device_inventory.modelDeviceInventoryEnabled()) return null;
        return &device;
    }
};

// Bridge to the kernel's real NVMe data plane (src/kernel/drivers/nvme_hw.zig).
// When a real NVMe controller is brought up (QEMU `-device nvme` or the first
// target), the booted storage backend uses it for genuine persistence across
// reboots. Host builds get inert stubs.
const nvme_bridge = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn zigosStorageBootstrapNvmeAttached() callconv(.c) bool;
        extern fn zigosStorageBootstrapNvmeSectorCount() callconv(.c) u64;
        pub extern fn zigosStorageBootstrapNvmeRead(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool;
        pub extern fn zigosStorageBootstrapNvmeWrite(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool;
        pub extern fn zigosStorageBootstrapNvmeFlush() callconv(.c) bool;
        pub fn attached() bool {
            return zigosStorageBootstrapNvmeAttached();
        }
        pub fn sectorCount() u64 {
            return zigosStorageBootstrapNvmeSectorCount();
        }
    }
else
    struct {
        pub fn attached() bool {
            return false;
        }
        pub fn sectorCount() u64 {
            return 0;
        }
        pub fn zigosStorageBootstrapNvmeRead(_: u64, _: [*]u8, _: usize) callconv(.c) bool {
            return false;
        }
        pub fn zigosStorageBootstrapNvmeWrite(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return false;
        }
        pub fn zigosStorageBootstrapNvmeFlush() callconv(.c) bool {
            return false;
        }
    };

const HostedStorageDataPlane = struct {
    var image = [_]u8{0} ** booted_storage_image_bytes;

    fn reset() void {
        @memset(image[0..], 0);
    }

    fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
        const buffer = buffer_ptr[0..buffer_len];
        if (buffer.len == 0 or buffer.len % storage_volume_mod.sector_size != 0) return false;
        const start = @as(usize, @intCast(start_lba)) * storage_volume_mod.sector_size;
        const end = start + buffer.len;
        if (end > image.len) return false;
        @memcpy(buffer, image[start..end]);
        return true;
    }

    fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
        const buffer = buffer_ptr[0..buffer_len];
        if (buffer.len == 0 or buffer.len % storage_volume_mod.sector_size != 0) return false;
        const start = @as(usize, @intCast(start_lba)) * storage_volume_mod.sector_size;
        const end = start + buffer.len;
        if (end > image.len) return false;
        @memcpy(image[start..end], buffer);
        return true;
    }

    fn flush() callconv(.c) bool {
        return true;
    }
};

const BootedStorageDataPlane = struct {
    fn reset() void {
        if (comptime builtin.target.os.tag != .freestanding) {
            HostedStorageDataPlane.reset();
        }
    }

    fn activate(device_id: u64) ?storage_volume_mod.Backend {
        if (device_id != device_inventory.deviceIdForClass(.storage_controller)) return null;
        if (nvme_bridge.attached()) {
            const nvme_sectors = nvme_bridge.sectorCount();
            // Real persistence: report the device's true capacity and never floor
            // it. If the namespace cannot hold the full volume layout plus the
            // restart-probe scratch range, fail closed (return null -> the
            // production storage gate refuses) rather than advertising a phantom
            // 1554-sector device whose writes would address LBAs past the
            // namespace and fail silently per sector at runtime.
            if (nvme_sectors < booted_storage_sector_count) return null;
            return .{
                .sector_count = nvme_sectors,
                .read = nvme_bridge.zigosStorageBootstrapNvmeRead,
                .write = nvme_bridge.zigosStorageBootstrapNvmeWrite,
                .flush = nvme_bridge.zigosStorageBootstrapNvmeFlush,
            };
        }
        if (comptime builtin.target.os.tag == .freestanding) {
            // Freestanding boots must use a brokered device publication or the
            // real NVMe bridge. Never turn missing hardware into ephemeral disk.
            return null;
        } else {
            return .{
                .sector_count = booted_storage_sector_count,
                .read = HostedStorageDataPlane.read,
                .write = HostedStorageDataPlane.write,
                .flush = HostedStorageDataPlane.flush,
            };
        }
    }
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

        if (!bootstrap_driver_port.activeStorageWrite(service_id, storage_restart_scratch_lba, expected[0..])) return false;
        if (!bootstrap_driver_port.activeStorageRead(service_id, storage_restart_scratch_lba, readback[0..])) return false;
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
            storage_restart_scratch_lba,
            partial_attempt[0 .. storage_volume_mod.sector_size / 2],
        );
        if (!self.partial_transfer_rejected) return false;

        var readback: [storage_volume_mod.sector_size]u8 = undefined;
        @memset(readback[0..], 0);
        if (!bootstrap_driver_port.activeStorageRead(service_id, storage_restart_scratch_lba, readback[0..])) return false;
        return std.mem.eql(u8, expected, readback[0..]);
    }

    fn rejectStaleAccessAfterGenerationChange(self: *@This()) bool {
        const session = self.old_controller_session orelse return false;
        var stale_read: [storage_volume_mod.sector_size]u8 = undefined;
        self.stale_authority_rejected = !bootstrap_driver_port.storageSessionIsCurrent(&session);
        self.stale_dma_access_rejected = !device_broker.brokeredDmaBufferStillValid(session.brokered_dma_buffer);
        self.stale_access_rejected = !bootstrap_driver_port.activeStorageRead(
            session.service_id,
            storage_restart_scratch_lba,
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

        if (!readRestartProbeStorage(service_id, storage_restart_scratch_lba, readback[0..])) return false;
        if (!std.mem.eql(u8, before_expected[0..], readback[0..])) return false;

        @memset(readback[0..], 0);
        if (!writeRestartProbeStorage(service_id, storage_restart_scratch_lba + 1, after_expected[0..])) return false;
        if (!readRestartProbeStorage(service_id, storage_restart_scratch_lba + 1, readback[0..])) return false;
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
            storage_restart_scratch_lba,
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
            86,
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
    return proveDriverCrashRestart(env, state, kernel_port, service_bindings);
}

pub fn bootServices(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *support.ServiceBindings,
) bool {
    seedHostedModelDeviceInventory();
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
        recordBootFailure(env, support.serviceId(state, entry.class), entry.boot_tick, err);
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
            recordBootFailure(env, support.serviceId(state, entry.class), entry.boot_tick, err);
            return false;
        };
    }
    return true;
}

fn seedHostedModelDeviceInventory() void {
    // Seed absent classes for host builds and explicitly modeled freestanding
    // boots. Real hardware keeps strict detected-inventory binding.
    if (builtin.target.os.tag == .freestanding and !device_inventory.modelDeviceInventoryEnabled()) return;

    const hosted_xhci_device_id = 0x8086_A0ED_0001;
    const hosted_nvme_device_id = 0x8086_9A0B_0001;

    ensureHostedModelProductionDevice(.network_adapter, 0x8086_15F2_0001, .intel_i225_lm_inventory);
    const storage_record = device_inventory.recordForClass(.storage_controller);
    if (!storage_record.detected or
        (device_inventory.modelDeviceInventoryEnabled() and
            !device_inventory.sourceCanBindProductionDriver(storage_record.device_class, storage_record.source, storage_record.device_id)))
    {
        device_inventory.registerDetected(.storage_controller, hosted_nvme_device_id, .nvme_pci_inventory, false);
    }
    ensureHostedModelProductionDevice(.usb_controller, hosted_xhci_device_id, .xhci_inventory);
    ensureHostedModelProductionDevice(.graphics_adapter, 0x8086_9A49_0001, .pci_inventory);
    ensureHostedModelProductionDevice(.audio_print_io, 0x8086_A0C8_0001, .pci_inventory);
    const input_record = device_inventory.recordForClass(.input_device);
    if (!device_inventory.sourceCanBindProductionDriver(input_record.device_class, input_record.source, input_record.device_id)) {
        device_inventory.registerDetected(.input_device, hosted_xhci_device_id, .xhci_inventory, false);
    }
    ensureHostedModelProductionDevice(.compositor_policy, 0xC0DE_9001, .platform_policy);
}

fn ensureHostedModelProductionDevice(
    device_class: driver_service.DeviceClass,
    device_id: u64,
    source: device_inventory.DetectionSource,
) void {
    const record = device_inventory.recordForClass(device_class);
    if (device_inventory.sourceCanBindProductionDriver(record.device_class, record.source, record.device_id)) return;
    device_inventory.registerDetected(device_class, device_id, source, false);
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
        recordBootFailure(env, state.services.storage_service.id, 52, err);
        return false;
    };

    const network_driver = attachBootstrapDriver(
        env,
        state,
        kernel_port,
        state.services.network_service.id,
        service_bindings.bindingFor(.network_stack).task_id,
        state.ids.network_service,
        .network_adapter,
        .none,
        "zigos.system.network-stack",
        53,
    ) orelse return false;
    const storage_driver = attachBootstrapDriver(
        env,
        state,
        kernel_port,
        state.services.storage_service.id,
        storage_driver_task.task_id,
        state.ids.storage_service,
        .storage_controller,
        .kernel_bootstrap_broker,
        "zigos.system.storage-driver",
        54,
    ) orelse return false;
    if (bootstrap_driver_port.storagePublication() == null) {
        const published_storage = bootstrap_driver_port.publishStorageActivator(
            storage_driver.device_id,
            "zigos.system.storage-driver",
            BootedStorageDataPlane.activate,
            false,
        ) catch false;
        if (!published_storage) {
            recordBootFailure(env, state.services.storage_service.id, 54, error.InvalidBootstrapTransport);
            return false;
        }
    }
    const graphics_driver = attachBootstrapDriver(
        env,
        state,
        kernel_port,
        state.services.compositor_service.id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        state.ids.compositor_service,
        .graphics_adapter,
        .none,
        "zigos.system.compositor",
        55,
    ) orelse return false;
    const usb_driver = attachBootstrapDriver(
        env,
        state,
        kernel_port,
        state.services.compositor_service.id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        state.ids.compositor_service,
        .usb_controller,
        .none,
        "zigos.system.compositor",
        56,
    ) orelse return false;
    const input_driver = attachBootstrapDriver(
        env,
        state,
        kernel_port,
        state.services.compositor_service.id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        state.ids.compositor_service,
        .input_device,
        .none,
        "zigos.system.compositor",
        57,
    ) orelse return false;
    const audio_driver = attachBootstrapDriver(
        env,
        state,
        kernel_port,
        state.services.media_service.id,
        service_bindings.bindingFor(.media_print_helpers).task_id,
        state.ids.media_service,
        .audio_print_io,
        .none,
        "zigos.system.media-print",
        58,
    ) orelse return false;
    const compositor_policy_driver = attachBootstrapDriver(
        env,
        state,
        kernel_port,
        state.services.compositor_service.id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        state.ids.compositor_service,
        .compositor_policy,
        .none,
        "zigos.system.compositor",
        59,
    ) orelse return false;

    if (bootstrap_driver_port.networkPublication() == null) {
        const published_network = bootstrap_driver_port.publishNetworkActivator(
            network_driver.device_id,
            "zigos.system.network-stack",
            BootedNetworkDataPlane.activate,
            false,
        ) catch false;
        if (!published_network) {
            recordBootFailure(env, state.services.network_service.id, 53, error.InvalidBootstrapTransport);
            return false;
        }
    }
    if (!publishBootedDeviceDataPlane(env, state.services.compositor_service.id, graphics_driver, "zigos.system.compositor", 55)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.compositor_service.id, usb_driver, "zigos.system.compositor", 56)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.compositor_service.id, input_driver, "zigos.system.compositor", 57)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.media_service.id, audio_driver, "zigos.system.media-print", 58)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.compositor_service.id, compositor_policy_driver, "zigos.system.compositor", 59)) return false;

    const network_activation_mode = activateBootstrapDriver(env, state.services.network_service.id, network_driver, 53) orelse return false;
    const storage_activation_mode = activateBootstrapDriver(env, state.services.storage_service.id, storage_driver, 54) orelse return false;
    _ = activateBootstrapDriver(env, state.services.compositor_service.id, graphics_driver, 55) orelse return false;
    _ = activateBootstrapDriver(env, state.services.compositor_service.id, usb_driver, 56) orelse return false;
    _ = activateBootstrapDriver(env, state.services.compositor_service.id, input_driver, 57) orelse return false;
    _ = activateBootstrapDriver(env, state.services.media_service.id, audio_driver, 58) orelse return false;
    _ = activateBootstrapDriver(env, state.services.compositor_service.id, compositor_policy_driver, 59) orelse return false;
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
        common.printBootMarker(boot_markers.service_boot_driver_service_storage_ready);
    }

    if (service_bootstrap.contractsReady(env.service_directory)) {
        common.printBootMarker(boot_markers.service_boot_service_contracts_ready);
    }
    return true;
}

fn attachBootstrapDriver(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
    device_class: driver_service.DeviceClass,
    bootstrap_transport: driver_service.BootstrapTransport,
    driver_bundle_id: []const u8,
    tick: u64,
) ?*driver_service.DriverRecord {
    return service_bootstrap.attachDriver(
        kernel_port,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        state.policy_capability.id,
        0,
        service_id,
        task_id,
        owner,
        device_class,
        bootstrap_transport,
        driver_bundle_id,
        tick,
    ) catch |err| {
        recordBootFailure(env, service_id, tick, err);
        return null;
    };
}

fn activateBootstrapDriver(
    env: *const support.Environment,
    service_id: u64,
    driver: *const driver_service.DriverRecord,
    tick: u64,
) ?driver_runtime_mod.ActivationMode {
    return env.driver_runtime.activateModeAt(driver, tick) catch |err| {
        recordBootFailure(env, service_id, tick, err);
        return null;
    };
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

    recordBootFailure(env, service_id, tick, error.InvalidBootstrapTransport);
    return false;
}

pub fn connectClient(
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
                .memory_bytes = units.kibibytes(512),
                .endpoint_slots = 16,
                .shared_memory_bytes = units.kibibytes(64),
                .background_allowed = false,
            },
            .local_only = true,
        },
        env.userspace_scheduler,
    ) catch |err| {
        recordBootFailure(env, state.services.service_registry.id, 56, err);
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
        recordBootFailure(env, state.services.service_registry.id, 56, err);
        return false;
    };
    env.runtime.grantCapability(service_client_task.id, service_client_authority.id) catch |err| {
        recordBootFailure(env, state.services.service_registry.id, 56, err);
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
            recordBootFailure(env, support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), err);
            return false;
        };
        const registry_connection = env.service_directory.connect(entry.interface) catch |err| {
            recordBootFailure(env, support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), err);
            return false;
        };
        _ = kernel_port.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, connect_request_id, service_client_task.id),
            .endpoint_capability_id = client_endpoint.capability_id,
            .peer_endpoint_capability_id = registry_connection.endpoint_capability_id,
            .peer_endpoint_id = binding.endpoint_id,
        }, 57 + @as(u64, @intCast(index))) catch |err| {
            recordBootFailure(env, support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), err);
            return false;
        };
        env.runtime.audit(service_client_task.id, .{
            .kind = .service_connected,
            .detail = @truncate(registry_connection.service_id),
            .tick = 57 + @as(u64, @intCast(index)),
        }) catch |err| {
            recordBootFailure(env, support.serviceId(state, entry.class), 57 + @as(u64, @intCast(index)), err);
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
    kernel_port: *component_port.KernelPort,
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
        recordBootFailure(env, state.services.network_service.id, 70, err);
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
        recordBootFailure(env, state.services.network_service.id, 72, err);
        return false;
    };
    if (recovery_runtime.rehost_count == 1 and
        recovery_runtime.deactivation_count == 1 and
        recovery_runtime.activation_count == 1 and
        recovery_runtime.last_process_generation >= 2)
    {
        common.printBootMarker(boot_markers.service_boot_driver_rehost_ok);
    } else {
        recordBootFailure(env, state.services.network_service.id, 72, error.MissingBootstrapLaunch);
        return false;
    }
    if (env.supervisor.hasDiagnostic(state.services.network_service.id, .restart_completed) and
        (env.driver_directory.findByService(state.services.network_service.id) orelse return false).restart_generation == 2)
    {
        common.printBootMarker(boot_markers.service_boot_supervisor_restart_ok);
        common.printBootMarker(boot_markers.service_boot_supervisor_restart_without_reboot);
    }

    return proveStorageDriverRestartIo(env, state, kernel_port) and proveAcceleratorDriverQueueEvents(env, state);
}

pub fn proveStorageDriverRestartIo(
    env: *const support.Environment,
    state: *const support.BootstrapState,
    kernel_port: *component_port.KernelPort,
) bool {
    var storage_probe = StorageRestartProbe{};
    if (!storage_probe.verifyBeforeRestart(state.services.storage_service.id)) {
        recordBootFailure(env, state.services.storage_service.id, 80, error.MissingBootstrapLaunch);
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
        recordBootFailure(env, state.services.storage_service.id, 81, err);
        return false;
    };

    const storage_driver = env.driver_directory.findByService(state.services.storage_service.id) orelse return false;
    const expected_storage_data_plane = storage_recovery.userspace_brokered_data_plane or
        bootstrap_driver_port.activeStorageControllerSession(state.services.storage_service.id) != null;
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
        recordBootFailure(env, state.services.storage_service.id, 83, error.MissingBootstrapLaunch);
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_dma_domain_programmed);
    common.printBootMarker(boot_markers.service_boot_storage_brokered_dma_buffer_ok);
    common.printBootMarker(boot_markers.service_boot_storage_controller_fault_contained);
    common.printBootMarker(boot_markers.service_boot_storage_partial_transfer_rejected);
    common.printBootMarker(boot_markers.service_boot_storage_stale_authority_rejected);
    common.printBootMarker(boot_markers.service_boot_storage_stale_dma_access_rejected);
    common.printBootMarker(boot_markers.service_boot_storage_stale_access_rejected);

    if (!storage_probe.verifyReboundSession(state.services.storage_service.id, storage_driver) or
        !storage_probe.rebound_dma_domain_programmed or
        !storage_probe.rebound_brokered_dma_buffer_ready)
    {
        recordBootFailure(env, state.services.storage_service.id, 84, error.MissingBootstrapLaunch);
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_rebind_ok);

    if (!storage_probe.verifyBrokerRevocationRecovery(state.services.storage_service.id, storage_driver, kernel_port) or
        !storage_probe.controller_revoke_rejected or
        !storage_probe.stale_broker_session_rejected or
        !storage_probe.republished_session_ready)
    {
        recordBootFailure(env, state.services.storage_service.id, 84, error.MissingBootstrapLaunch);
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_controller_revoke_rejected);
    common.printBootMarker(boot_markers.service_boot_storage_republish_after_revoke_ok);

    if (!storage_probe.verifyAfterRestart(state.services.storage_service.id)) {
        recordBootFailure(env, state.services.storage_service.id, 85, error.MissingBootstrapLaunch);
        return false;
    }
    common.printBootMarker(boot_markers.service_boot_storage_io_after_restart_ok);
    return true;
}

fn proveAcceleratorDriverQueueEvents(
    env: *const support.Environment,
    state: *const support.BootstrapState,
) bool {
    var scheduler = accelerator_scheduler.Controller.init();
    scheduler.configure(.{
        .media_available = true,
    });
    scheduler.requireBrokeredEngineQueues();

    var session = accelerator_driver_task.createQueueSession(.media, state.services.storage_service.id, state.services.storage_service.id, 3) catch |err| {
        recordBootFailure(env, state.services.storage_service.id, 86, err);
        return false;
    };
    session.recordHardwareQueueOwnership(9, 1) catch |err| {
        recordBootFailure(env, state.services.storage_service.id, 86, err);
        return false;
    };
    session.publishQueueEvent(&scheduler) catch |err| {
        recordBootFailure(env, state.services.storage_service.id, 86, err);
        return false;
    };
    common.printBootMarker(boot_markers.service_boot_accelerator_queue_owned);

    const claim = scheduler.claim(.{
        .task_id = state.services.storage_service.id,
        .request = .{
            .class = .media_export,
            .wants_media_engine = true,
        },
        .require_accelerator = true,
    }) catch |err| {
        recordBootFailure(env, state.services.storage_service.id, 87, err);
        return false;
    };
    if (scheduler.releaseClaim(claim.id, null)) |_| {
        recordBootFailure(env, state.services.storage_service.id, 87, error.QueueCompletionMissing);
        return false;
    } else |err| {
        if (err != error.QueueCompletionMissing) {
            recordBootFailure(env, state.services.storage_service.id, 87, err);
            return false;
        }
    }

    session.recordCompletionInterrupt(10) catch |err| {
        recordBootFailure(env, state.services.storage_service.id, 88, err);
        return false;
    };
    session.publishQueueEvent(&scheduler) catch |err| {
        recordBootFailure(env, state.services.storage_service.id, 88, err);
        return false;
    };
    if (!(scheduler.releaseClaim(claim.id, null) catch |err| {
        recordBootFailure(env, state.services.storage_service.id, 88, err);
        return false;
    })) return false;

    common.printBootMarker(boot_markers.service_boot_accelerator_completion_interrupt);
    return true;
}

test "hosted model inventory seeds target-grade nvme storage" {
    device_inventory.reset();
    device_inventory.setModelDeviceInventory(false);
    seedHostedModelDeviceInventory();
    const modeled_storage = device_inventory.recordForClass(.storage_controller);
    try std.testing.expectEqual(device_inventory.DetectionSource.nvme_pci_inventory, modeled_storage.source);
    try std.testing.expectEqual(@as(u64, 0x8086_9A0B_0001), try device_inventory.requireProductionDriverDeviceId(.storage_controller));
}

fn bootFailureCode(err: anyerror) u32 {
    return @truncate(native_util.fnv1a64(@errorName(err)));
}

fn recordBootFailure(env: *const support.Environment, service_id: u64, tick: u64, err: anyerror) void {
    _ = env.supervisor.recordCrash(service_id, tick, bootFailureCode(err));
}
