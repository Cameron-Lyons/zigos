const builtin = @import("builtin");
const authorization_clock = @import("authorization_clock.zig");
const boot_markers = @import("../../kernel/boot/markers.zig");
const component_port = @import("../kernel_api/component_port.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const xhci_driver_task = @import("../drivers/xhci_driver_task.zig");
const device_inventory = @import("../drivers/device_inventory.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const native_util = @import("../core/util.zig");
const std = @import("std");
const service_bootstrap = @import("service_bootstrap.zig");
const service_catalog = @import("service_catalog.zig");
const storage_volume_mod = @import("../storage/storage_volume.zig");
const support = @import("session_manager_support.zig");
const task_runtime = @import("../task/task_runtime.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const nvme_device_lba_bytes: usize = 512;
/// First sector past the volume that the verification restart proofs use as scratch.
pub const storage_restart_scratch_lba: u64 = storage_volume_mod.required_device_sectors + 16;

comptime {
    if (builtin.target.os.tag == .freestanding) {
        const nvme_hw = @import("../../kernel/drivers/nvme_hw.zig");
        if (nvme_hw.SECTOR_BYTES != nvme_device_lba_bytes) {
            @compileError("boot storage plane must translate NVMe LBAs from the volume block size");
        }
    }
}
const storage_restart_probe_sectors: u64 = 2;
const booted_storage_sector_count: u64 = storage_restart_scratch_lba + storage_restart_probe_sectors;
const booted_storage_image_bytes: usize = @as(usize, @intCast(booted_storage_sector_count)) * storage_volume_mod.sector_size;

const network_bridge = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn zigosNetworkBootstrapAttached() callconv(.c) bool;
        extern fn zigosNetworkBootstrapSend(
            destination_ptr: [*]const u8,
            payload_ptr: [*]const u8,
            payload_len: usize,
        ) callconv(.c) bool;
        extern fn zigosNetworkBootstrapReceive(
            output_ptr: [*]u8,
            output_capacity: usize,
            output_len: *usize,
        ) callconv(.c) u8;
        extern fn zigosNetworkBootstrapWorkPending() callconv(.c) bool;
        extern fn zigosNetworkBootstrapNextWake(deadline: *u64) callconv(.c) bool;
        extern fn zigosNetworkBootstrapMac(output: [*]u8) callconv(.c) bool;

        pub fn attached() bool {
            return zigosNetworkBootstrapAttached();
        }

        pub fn send(destination: [6]u8, payload: []const u8) bool {
            return zigosNetworkBootstrapSend(&destination, payload.ptr, payload.len);
        }

        pub fn receive(output: []u8) bootstrap_driver_port.ReceiveResult {
            var length: usize = 0;
            const status = zigosNetworkBootstrapReceive(output.ptr, output.len, &length);
            return .{
                .status = switch (status) {
                    0 => .empty,
                    1 => .frame,
                    2 => .dropped,
                    else => .failed,
                },
                .length = std.math.cast(u16, length) orelse std.math.maxInt(u16),
            };
        }

        pub fn workPending() bool {
            return zigosNetworkBootstrapWorkPending();
        }

        pub fn nextWake() ?u64 {
            var deadline: u64 = 0;
            return if (zigosNetworkBootstrapNextWake(&deadline)) deadline else null;
        }

        pub fn mac() ?[6]u8 {
            var address: [6]u8 = undefined;
            if (!zigosNetworkBootstrapMac(&address)) return null;
            return address;
        }
    }
else
    struct {
        pub fn attached() bool {
            return false;
        }

        pub fn send(_: [6]u8, _: []const u8) bool {
            return false;
        }

        pub fn receive(_: []u8) bootstrap_driver_port.ReceiveResult {
            return .{ .status = .empty };
        }

        pub fn workPending() bool {
            return false;
        }

        pub fn nextWake() ?u64 {
            return null;
        }

        pub fn mac() ?[6]u8 {
            return null;
        }
    };

const BootedNetworkDataPlane = struct {
    fn send(destination: [6]u8, data: []const u8) bool {
        if (network_bridge.attached()) return network_bridge.send(destination, data);
        return builtin.target.os.tag != .freestanding or device_inventory.modelDeviceInventoryEnabled();
    }

    fn receive(output: []u8) bootstrap_driver_port.ReceiveResult {
        if (network_bridge.attached()) return network_bridge.receive(output);
        if (builtin.target.os.tag != .freestanding or device_inventory.modelDeviceInventoryEnabled()) {
            return .{ .status = .empty };
        }
        return .{ .status = .failed };
    }

    fn workPending() bool {
        return network_bridge.attached() and network_bridge.workPending();
    }

    fn nextWake() ?u64 {
        return network_bridge.nextWake();
    }

    fn getMacAddress() [6]u8 {
        if (network_bridge.mac()) |address| return address;
        return .{ 0x02, 0x5A, 0x47, 0x00, 0x00, 0x01 };
    }

    const device = bootstrap_driver_port.NetworkDevice{
        .send = send,
        .receive = receive,
        .workPending = workPending,
        .nextWake = nextWake,
        .getMacAddress = getMacAddress,
    };

    // Retain hardware callbacks after containment. Losing attachment must not
    // turn a failed real-device send into a successful model-inventory send.
    const hardware_device = bootstrap_driver_port.NetworkDevice{
        .send = network_bridge.send,
        .receive = network_bridge.receive,
        .workPending = network_bridge.workPending,
        .nextWake = network_bridge.nextWake,
        .getMacAddress = hardwareMacAddress,
    };

    fn hardwareMacAddress() [6]u8 {
        return network_bridge.mac() orelse @as([6]u8, @splat(0));
    }

    fn activate(device_id: u64) ?*const bootstrap_driver_port.NetworkDevice {
        if (device_id != device_inventory.deviceIdForClass(.network_adapter)) return null;
        if (network_bridge.attached()) return &hardware_device;
        if (builtin.target.os.tag == .freestanding and
            !network_bridge.attached() and
            !device_inventory.modelDeviceInventoryEnabled()) return null;
        return &device;
    }
};

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
    var image = @as([booted_storage_image_bytes]u8, @splat(0));

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

fn readNvmeVolumeBlocks(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
    const device_lba = storage_volume_mod.deviceLbaForVolumeTransfer(
        start_lba,
        buffer_len,
        nvme_device_lba_bytes,
    ) orelse return false;
    return nvme_bridge.zigosStorageBootstrapNvmeRead(device_lba, buffer_ptr, buffer_len);
}

fn writeNvmeVolumeBlocks(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
    const device_lba = storage_volume_mod.deviceLbaForVolumeTransfer(
        start_lba,
        buffer_len,
        nvme_device_lba_bytes,
    ) orelse return false;
    return nvme_bridge.zigosStorageBootstrapNvmeWrite(device_lba, buffer_ptr, buffer_len);
}

const BootedStorageDataPlane = struct {
    fn reset() void {
        if (comptime builtin.target.os.tag != .freestanding) {
            HostedStorageDataPlane.reset();
        }
    }

    fn activate(device_id: u64) ?storage_volume_mod.Backend {
        if (device_id != device_inventory.deviceIdForClass(.storage_controller)) return null;
        if (nvme_bridge.attached()) {
            const device_sectors = nvme_bridge.sectorCount();
            const volume_sectors = storage_volume_mod.volumeSectorsFromDeviceSectors(
                device_sectors,
                nvme_device_lba_bytes,
            ) orelse return null;
            if (volume_sectors < booted_storage_sector_count) return null;
            return .{
                .sector_count = volume_sectors,
                .read = readNvmeVolumeBlocks,
                .write = writeNvmeVolumeBlocks,
                .flush = nvme_bridge.zigosStorageBootstrapNvmeFlush,
            };
        }
        if (comptime builtin.target.os.tag == .freestanding) {
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

pub fn resetBootedDataPlanes() void {
    BootedStorageDataPlane.reset();
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
    const index = service_catalog.orderedServiceIndex(.service_registry).?;
    if (service_bindings.bindings[index].task_id != 0) return true;
    const entry = service_catalog.serviceContractForClass(.service_registry).?;
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
    for (service_catalog.ordered_service_contracts, 0..) |entry, index| {
        if (service_bindings.bindings[index].task_id != 0) continue;
        service_bindings.bindings[index] = launchService(env, state, kernel_port, entry) catch |err| {
            recordBootFailure(env, support.serviceId(state, entry.class), entry.boot_tick, err);
            return false;
        };
    }
    return true;
}

fn seedHostedModelDeviceInventory() void {
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
    entry: service_catalog.ServiceContract,
) service_bootstrap.Error!service_bootstrap.ServiceBinding {
    try task_runtime.grantCapabilityToTask(state.session_task, state.session_capability.id);
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
        "zigos.system.drivers",
        .storage_controller,
        328,
        52,
    ) catch |err| {
        recordBootFailure(env, state.services.get(.storage_object).id, 52, err);
        return false;
    };

    const network_driver = attachBootstrapDriver(
        env,
        state,
        state.services.get(.network_stack).id,
        service_bindings.bindingFor(.network_stack).task_id,
        .network_adapter,
        .none,
        "zigos.system.network",
        53,
    ) orelse return false;
    const storage_driver = attachBootstrapDriver(
        env,
        state,
        state.services.get(.storage_object).id,
        storage_driver_task.task_id,
        .storage_controller,
        .kernel_bootstrap_broker,
        "zigos.system.drivers",
        54,
    ) orelse return false;
    if (bootstrap_driver_port.storagePublication() == null) {
        const published_storage = bootstrap_driver_port.publishStorageActivator(
            storage_driver.device_id,
            "zigos.system.drivers",
            BootedStorageDataPlane.activate,
            false,
        ) catch false;
        if (!published_storage) {
            recordBootFailure(env, state.services.get(.storage_object).id, 54, error.InvalidBootstrapTransport);
            return false;
        }
    }
    const graphics_driver = attachBootstrapDriver(
        env,
        state,
        state.services.get(.compositor_ui_session).id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        .graphics_adapter,
        .none,
        "zigos.system.display",
        55,
    ) orelse return false;
    const usb_driver = attachBootstrapDriver(
        env,
        state,
        state.services.get(.compositor_ui_session).id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        .usb_controller,
        .none,
        "zigos.system.display",
        56,
    ) orelse return false;
    xhci_driver_task.bindTaskId(service_bindings.bindingFor(.compositor_ui_session).task_id);
    const input_driver = attachBootstrapDriver(
        env,
        state,
        state.services.get(.compositor_ui_session).id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        .input_device,
        .none,
        "zigos.system.display",
        57,
    ) orelse return false;
    const audio_driver = attachBootstrapDriver(
        env,
        state,
        state.services.get(.media_print_helpers).id,
        service_bindings.bindingFor(.media_print_helpers).task_id,
        .audio_print_io,
        .none,
        "zigos.system.apps",
        58,
    ) orelse return false;
    const compositor_policy_driver = attachBootstrapDriver(
        env,
        state,
        state.services.get(.compositor_ui_session).id,
        service_bindings.bindingFor(.compositor_ui_session).task_id,
        .compositor_policy,
        .none,
        "zigos.system.display",
        59,
    ) orelse return false;

    if (bootstrap_driver_port.networkPublication() == null) {
        const published_network = bootstrap_driver_port.publishNetworkActivator(
            network_driver.device_id,
            "zigos.system.network",
            BootedNetworkDataPlane.activate,
            false,
        ) catch false;
        if (!published_network) {
            recordBootFailure(env, state.services.get(.network_stack).id, 53, error.InvalidBootstrapTransport);
            return false;
        }
    }
    if (!publishBootedDeviceDataPlane(env, state.services.get(.compositor_ui_session).id, graphics_driver, "zigos.system.display", 55)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.get(.compositor_ui_session).id, usb_driver, "zigos.system.display", 56)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.get(.compositor_ui_session).id, input_driver, "zigos.system.display", 57)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.get(.media_print_helpers).id, audio_driver, "zigos.system.apps", 58)) return false;
    if (!publishBootedDeviceDataPlane(env, state.services.get(.compositor_ui_session).id, compositor_policy_driver, "zigos.system.display", 59)) return false;

    const storage_activation_mode = activateBootstrapDriver(env, state.services.get(.storage_object).id, storage_driver, 54) orelse return false;
    const network_activation_mode = activateBootstrapDriver(env, state.services.get(.network_stack).id, network_driver, 53) orelse return false;
    _ = activateBootstrapDriver(env, state.services.get(.compositor_ui_session).id, graphics_driver, 55) orelse return false;
    _ = activateBootstrapDriver(env, state.services.get(.compositor_ui_session).id, usb_driver, 56) orelse return false;
    _ = activateBootstrapDriver(env, state.services.get(.compositor_ui_session).id, input_driver, 57) orelse return false;
    _ = activateBootstrapDriver(env, state.services.get(.media_print_helpers).id, audio_driver, 58) orelse return false;
    _ = activateBootstrapDriver(env, state.services.get(.compositor_ui_session).id, compositor_policy_driver, 59) orelse return false;
    if (network_activation_mode == .published_data_plane and storage_activation_mode == .published_data_plane) {
        common.printBootMarker(boot_markers.service_boot_driver_service_network_ready);
    }
    if (storage_activation_mode == .published_data_plane and storage_volume_mod.hasAttachedDevice()) {
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
    service_id: u64,
    task_id: u64,
    device_class: driver_service.DeviceClass,
    bootstrap_transport: driver_service.BootstrapTransport,
    driver_bundle_id: []const u8,
    tick: u64,
) ?*driver_service.DriverRecord {
    return service_bootstrap.attachDriver(
        env.runtime,
        env.capability_table,
        env.driver_directory,
        env.supervisor,
        state.ids.policy_authority,
        service_id,
        task_id,
        device_class,
        bootstrap_transport,
        driver_bundle_id,
        authorization_clock.at(tick),
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
    return env.driver_runtime.activateModeAt(driver, authorization_clock.at(tick)) catch |err| {
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

pub fn recordBootFailure(env: *const support.Environment, service_id: u64, tick: u64, err: anyerror) void {
    _ = env.supervisor.recordCrash(service_id, tick, bootFailureCode(err));
}
