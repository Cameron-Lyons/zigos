const std = @import("std");
const bootstrap_driver_port = @import("bootstrap_driver_port.zig");
const device_inventory = @import("device_inventory.zig");
const driver_service = @import("driver_service.zig");
const component_port = @import("../kernel_api/component_port.zig");
const storage_volume = @import("../storage/storage_volume.zig");
const units = @import("../core/units.zig");

pub const MAX_ACTIVATIONS: usize = 8;
pub const ACTIVATION_RECORD_SIZE_CEILING_BYTES: usize = 32;
pub const RUNTIME_SIZE_CEILING_BYTES: usize = 344;
pub const ACTIVATION_CLASS_COUNT: usize = @typeInfo(driver_service.DeviceClass).@"enum".field_names.len;
const ActivationSlotIndex = std.math.IntFittingRange(0, MAX_ACTIVATIONS - 1);

comptime {
    for (@typeInfo(driver_service.DeviceClass).@"enum".field_values, 0..) |field, class_index| {
        if (field != class_index) {
            @compileError("driver device classes must remain dense for direct activation lookup");
        }
    }
}

pub const ActivationMode = enum(u8) {
    control_only,
    published_data_plane,
};

pub const ActivationRecord = struct {
    service_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
    dma_domain_id: u64,
    mode: ActivationMode,
    activation_generation: u32,

    pub fn publisherSlice(self: *const ActivationRecord) []const u8 {
        if (self.mode == .control_only) return "";
        return bootstrap_driver_port.activePublicationPublisher(
            self.device_class,
            self.device_id,
            self.service_id,
        ) orelse "";
    }

    pub fn iommuEnforced(self: *const ActivationRecord) bool {
        return self.dma_domain_id != 0;
    }

    pub fn hasExclusiveClaim(self: *const ActivationRecord) bool {
        return self.mode != .control_only;
    }

    pub fn kernelBootstrap(self: *const ActivationRecord) bool {
        return bootstrap_driver_port.publicationUsesKernelBootstrap(self.device_class, self.device_id);
    }

    comptime {
        if (@sizeOf(@This()) > ACTIVATION_RECORD_SIZE_CEILING_BYTES) {
            @compileError("driver activation record exceeds its compact size ceiling");
        }
    }
};

pub const Error = error{
    ActivationTableFull,
    KernelBootstrapNotAuthorized,
    MissingDmaDomain,
};

pub const Runtime = struct {
    kernel_port: ?*component_port.KernelPort = null,
    slots: [MAX_ACTIVATIONS]?ActivationRecord = @splat(null),
    // A device class can move between services across hot-swaps, so each
    // class tracks the slot of its most recent activation.
    class_slots: [ACTIVATION_CLASS_COUNT]?ActivationSlotIndex = @splat(null),

    pub fn init() Runtime {
        return .{};
    }

    pub fn bindKernelPort(self: *Runtime, kernel_port: *component_port.KernelPort) void {
        self.kernel_port = kernel_port;
    }

    pub fn activateModeAt(
        self: *Runtime,
        driver: *const driver_service.DriverRecord,
        now_ticks: u64,
    ) Error!ActivationMode {
        const record = try self.activateAt(driver, now_ticks);
        return record.mode;
    }

    pub fn activateAt(
        self: *Runtime,
        driver: *const driver_service.DriverRecord,
        now_ticks: u64,
    ) Error!ActivationRecord {
        if (driver.dma_domain_id == 0) return error.MissingDmaDomain;
        var record = ActivationRecord{
            .service_id = driver.service_id,
            .device_id = driver.device_id,
            .device_class = driver.device_class,
            .dma_domain_id = driver.dma_domain_id,
            .mode = .control_only,
            .activation_generation = driver.restart_generation,
        };

        switch (driver.device_class) {
            .network_adapter => {
                if (bootstrap_driver_port.networkPublication()) |publication| {
                    if (publication.device_id == driver.device_id) {
                        if (publication.kernel_bootstrap and driver.bootstrap_transport != .kernel_bootstrap_broker) {
                            return error.KernelBootstrapNotAuthorized;
                        }
                        if (bootstrap_driver_port.activateNetworkDeviceForTask(
                            driver.device_id,
                            driver.service_id,
                            driver.owner_task_id,
                        )) {
                            record.mode = .published_data_plane;
                        }
                    }
                }
            },
            .storage_controller => {
                if (bootstrap_driver_port.storagePublication()) |publication| {
                    if (publication.device_id == driver.device_id) {
                        if (publication.kernel_bootstrap and driver.bootstrap_transport != .kernel_bootstrap_broker) {
                            return error.KernelBootstrapNotAuthorized;
                        }
                        if (bootstrap_driver_port.activateStorageBackend(
                            driver.device_id,
                            driver.service_id,
                            driver.authority_capability_id,
                            driver.owner_task_id,
                            driver.dma_domain_id,
                            now_ticks,
                            self.kernel_port,
                        )) {
                            record.mode = .published_data_plane;
                        }
                    }
                }
            },
            .usb_controller, .graphics_adapter, .audio_print_io, .input_device, .compositor_policy => {
                if (bootstrap_driver_port.deviceDataPlanePublication(driver.device_class)) |publication| {
                    if (publication.device_id == driver.device_id) {
                        if (publication.kernel_bootstrap) return error.KernelBootstrapNotAuthorized;
                        if (bootstrap_driver_port.activateDeviceDataPlane(driver.device_class, driver.device_id, driver.service_id)) {
                            record.mode = .published_data_plane;
                        }
                    }
                }
            },
        }

        return self.upsert(record);
    }

    pub fn findByClass(self: *const Runtime, device_class: driver_service.DeviceClass) ?ActivationRecord {
        const index = self.class_slots[@backingInt(device_class)] orelse return null;
        return self.slots[index];
    }

    pub fn deactivateDriver(self: *Runtime, service_id: u64, device_class: driver_service.DeviceClass) bool {
        const index = self.slotIndex(service_id, device_class) orelse return false;
        const activation = &self.slots[index].?;
        if (activation.hasExclusiveClaim()) {
            const released = switch (activation.device_class) {
                .network_adapter => bootstrap_driver_port.deactivateNetworkDevice(activation.service_id),
                .storage_controller => bootstrap_driver_port.deactivateStorageBackend(activation.service_id),
                .usb_controller, .graphics_adapter, .audio_print_io, .input_device, .compositor_policy => bootstrap_driver_port.deactivateDeviceDataPlane(activation.device_class, activation.service_id),
            };
            if (!released) return false;
        }
        activation.mode = .control_only;
        return true;
    }

    fn upsert(self: *Runtime, activation: ActivationRecord) Error!ActivationRecord {
        const index = self.slotIndex(activation.service_id, activation.device_class) orelse
            self.freeSlotIndex() orelse return error.ActivationTableFull;
        self.slots[index] = activation;
        self.class_slots[@backingInt(activation.device_class)] = index;
        return activation;
    }

    fn slotIndex(self: *const Runtime, service_id: u64, device_class: driver_service.DeviceClass) ?ActivationSlotIndex {
        for (self.slots, 0..) |slot, index| {
            const activation = slot orelse continue;
            if (activation.service_id == service_id and activation.device_class == device_class) return @intCast(index);
        }
        return null;
    }

    fn freeSlotIndex(self: *const Runtime) ?ActivationSlotIndex {
        for (self.slots, 0..) |slot, index| {
            if (slot == null) return @intCast(index);
        }
        return null;
    }

    comptime {
        if (@sizeOf(@This()) > RUNTIME_SIZE_CEILING_BYTES) {
            @compileError("driver runtime exceeds its compact size ceiling");
        }
    }
};

fn zeroActivation() ActivationRecord {
    return .{
        .service_id = 0,
        .device_id = 0,
        .device_class = .network_adapter,
        .dma_domain_id = 0,
        .mode = .control_only,
        .activation_generation = 0,
    };
}

test "driver runtime uses compact bounded activation metadata" {
    try std.testing.expect(!@hasField(Runtime, "next_activation_generation"));
    try std.testing.expectEqual(@as(usize, ACTIVATION_RECORD_SIZE_CEILING_BYTES), @sizeOf(ActivationRecord));
    try std.testing.expectEqual(@as(usize, RUNTIME_SIZE_CEILING_BYTES), @sizeOf(Runtime));
}

test "direct activation class slots follow the latest upsert" {
    var runtime = Runtime.init();
    var first = zeroActivation();
    first.service_id = 41;
    first.device_id = 401;
    first.device_class = .network_adapter;
    first.dma_domain_id = 4_001;
    first.activation_generation = 1;
    _ = try runtime.upsert(first);
    try std.testing.expectEqual(first.service_id, runtime.findByClass(.network_adapter).?.service_id);

    var second = first;
    second.service_id = 42;
    second.device_id = 402;
    second.dma_domain_id = 4_002;
    _ = try runtime.upsert(second);
    try std.testing.expectEqual(second.service_id, runtime.findByClass(.network_adapter).?.service_id);

    first.activation_generation = 2;
    _ = try runtime.upsert(first);
    const latest = runtime.findByClass(.network_adapter).?;
    try std.testing.expectEqual(first.service_id, latest.service_id);
    try std.testing.expectEqual(first.activation_generation, latest.activation_generation);
}

test "kernel bootstrap cannot publish network data-plane transports" {
    const FakeNetworkDevice = struct {
        fn send(_: [6]u8, _: []const u8) bool {
            return true;
        }

        fn getMacAddress() [6]u8 {
            return .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
        }

        const device = bootstrap_driver_port.NetworkDevice{
            .send = send,
            .receive = bootstrap_driver_port.noNetworkFrame,
            .getMacAddress = getMacAddress,
        };

        fn activate(device_id: u64) ?*const bootstrap_driver_port.NetworkDevice {
            if (device_id != 0x8086_15F2_0001) return null;
            return &device;
        }
    };

    if (!bootstrap_driver_port.reset()) @panic("storage lifecycle transition was refused");
    defer if (!bootstrap_driver_port.reset()) @panic("storage lifecycle transition was refused");

    try std.testing.expect(!(try bootstrap_driver_port.publishNetworkActivator(
        0x8086_15F2_0001,
        "i225",
        FakeNetworkDevice.activate,
        true,
    )));

    var directory = driver_service.Directory.init();
    const capability = @import("../kernel_api/capability.zig");
    var capabilities = capability.CapabilityTable.init();
    const driver_authority = try driver_service.mintDriverAuthority(&capabilities, .{
        .holder = .{ .kind = .service, .serial = 91 },
        .task_id = 901,
        .device_id = 0x8086_15F2_0001,
        .device_class = .network_adapter,
    });
    const driver = try directory.registerSigned(.{
        .service_id = 91,
        .owner_task_id = 901,
        .device_id = 0x8086_15F2_0001,
        .device_class = .network_adapter,
        .authority_capability_id = driver_authority.id,
        .capability_table = &capabilities,
        .requester = driver_authority.holder,
        .now_ticks = 1,
        .signer = "zigos-spec-driver",
    });

    var runtime = Runtime.init();
    const activation = try runtime.activateAt(driver, 1);
    try std.testing.expectEqual(ActivationMode.control_only, activation.mode);
    try std.testing.expect(!activation.hasExclusiveClaim());
}

test "runtime uses the activation tick when claiming storage authority" {
    const capability = @import("../kernel_api/capability.zig");
    const device_broker = @import("../kernel_api/device_broker.zig");
    const endpoint = @import("../kernel_api/endpoint.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const principal = @import("../core/principal.zig");
    const shared_memory = @import("../kernel_api/shared_memory.zig");
    const generated_image_fixtures = @import("../task/generated_image_fixtures.zig");
    const task_runtime = @import("../task/task_runtime.zig");
    const device_id: u64 = 0x0000_8086_5845_0001;

    if (!bootstrap_driver_port.reset()) @panic("storage lifecycle transition was refused");
    defer if (!bootstrap_driver_port.reset()) @panic("storage lifecycle transition was refused");
    device_broker.reset();
    defer device_broker.reset();
    device_inventory.reset();
    defer device_inventory.reset();
    if (!storage_volume.clearAttachedBackend()) @panic("storage lifecycle transition was refused");
    defer if (!storage_volume.clearAttachedBackend()) @panic("storage lifecycle transition was refused");

    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel: native_kernel.Kernel = undefined;
    kernel.initInPlace(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    defer kernel.deinit();
    var kernel_port = component_port.KernelPort.init(&kernel);

    const Backend = struct {
        fn read(_: u64, _: [*]u8, _: usize) callconv(.c) bool {
            return false;
        }

        fn write(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return false;
        }

        fn flush() callconv(.c) bool {
            return true;
        }
    };
    device_inventory.registerDetected(.storage_controller, device_id, .nvme_pci_inventory, false);
    const backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors,
        .read = Backend.read,
        .write = Backend.write,
        .flush = Backend.flush,
    };

    const storage_driver_lease_image = try generated_image_fixtures.storageDriverImage();
    const driver_task = try runtime.createTask(.{
        .owner = principal.PrincipalId{ .kind = .service, .serial = 30 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 30,
            .signed = true,
            .bundle_id = "zigos.system.storage-driver",
        },
        .userspace_image = &storage_driver_lease_image,
    });
    const device_capability = try driver_service.mintDriverAuthority(&capabilities, .{
        .holder = driver_task.owner,
        .task_id = driver_task.id,
        .device_id = device_id,
        .device_class = .storage_controller,
        .issued_at_ticks = 1,
        .expires_at_ticks = 5,
        .renewable = false,
    });
    try runtime.grantCapability(driver_task.id, device_capability.id);

    var directory = driver_service.Directory.init();
    const driver = try directory.registerSigned(.{
        .service_id = 30,
        .owner_task_id = driver_task.id,
        .device_id = device_id,
        .device_class = .storage_controller,
        .authority_capability_id = device_capability.id,
        .capability_table = &capabilities,
        .requester = driver_task.owner,
        .now_ticks = 2,
        .signer = "zigos-spec-driver",
        .bootstrap_transport = .kernel_bootstrap_broker,
    });
    try std.testing.expect(try bootstrap_driver_port.publishStorageBackend(
        driver.device_id,
        "zigos.system.storage-driver",
        backend,
        false,
    ));

    var driver_runtime = Runtime.init();
    driver_runtime.bindKernelPort(&kernel_port);
    const activation = try driver_runtime.activateAt(driver, 10);
    try std.testing.expectEqual(ActivationMode.control_only, activation.mode);
    try std.testing.expect(!storage_volume.hasAttachedDevice());
}

test "runtime treats driver restart after active storage I/O as a normal invariant" {
    const capability = @import("../kernel_api/capability.zig");
    const principal = @import("../core/principal.zig");

    const FakeBackend = struct {
        var image: []u8 = &.{};
        var activation_count: usize = 0;

        fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
            const buffer = buffer_ptr[0..buffer_len];
            const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
            const end = start + buffer.len;
            if (end > image.len) return false;
            @memcpy(buffer, image[start..end]);
            return true;
        }

        fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
            const buffer = buffer_ptr[0..buffer_len];
            const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
            const end = start + buffer.len;
            if (end > image.len) return false;
            @memcpy(image[start..end], buffer);
            return true;
        }

        fn flush() callconv(.c) bool {
            return true;
        }

        fn activate(device_id: u64) ?storage_volume.Backend {
            if (device_id != 0x0000_8086_5845_00A1) return null;
            activation_count += 1;
            return .{
                .sector_count = storage_volume.required_device_sectors,
                .read = read,
                .write = write,
                .flush = flush,
            };
        }
    };

    if (!bootstrap_driver_port.reset()) @panic("storage lifecycle transition was refused");
    defer if (!bootstrap_driver_port.reset()) @panic("storage lifecycle transition was refused");
    device_inventory.reset();
    defer device_inventory.reset();
    if (!storage_volume.clearAttachedBackend()) @panic("storage lifecycle transition was refused");
    defer if (!storage_volume.clearAttachedBackend()) @panic("storage lifecycle transition was refused");

    var image = @as([storage_volume.image_bytes]u8, @splat(0));
    FakeBackend.image = &image;
    FakeBackend.activation_count = 0;

    const device_id: u64 = 0x0000_8086_5845_00A1;
    const service_id: u64 = 301;
    const task_id: u64 = 3_001;
    device_inventory.registerDetected(.storage_controller, device_id, .nvme_pci_inventory, false);
    try std.testing.expect(try bootstrap_driver_port.publishStorageActivator(
        device_id,
        "nvme-userspace",
        FakeBackend.activate,
        false,
    ));

    var capabilities = capability.CapabilityTable.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = service_id };
    const authority = try driver_service.mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = task_id,
        .device_id = device_id,
        .device_class = .storage_controller,
    });
    var directory = driver_service.Directory.init();
    const driver = try directory.registerSigned(.{
        .service_id = service_id,
        .owner_task_id = task_id,
        .device_id = device_id,
        .device_class = .storage_controller,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = owner,
        .now_ticks = 1,
        .signer = "zigos-storage-driver",
    });

    var runtime = Runtime.init();
    const activation = try runtime.activateAt(driver, 1);
    try std.testing.expectEqual(ActivationMode.published_data_plane, activation.mode);
    try std.testing.expectEqual(driver.restart_generation, activation.activation_generation);
    try std.testing.expectEqual(@as(usize, 1), FakeBackend.activation_count);
    try std.testing.expect(storage_volume.hasProductionStorageBackend());

    var before_restart = @as([storage_volume.sector_size]u8, @splat(0x44));
    const before_label = "before-restart";
    @memcpy(before_restart[0..before_label.len], before_label);
    try std.testing.expect(bootstrap_driver_port.activeStorageWrite(service_id, 4, before_restart[0..]));

    const previous_dma_domain = driver.dma_domain_id;
    try std.testing.expect(runtime.deactivateDriver(service_id, .storage_controller));
    try std.testing.expect(directory.markRestarted(driver));
    try std.testing.expect(driver.dma_domain_id != previous_dma_domain);
    const restarted = try runtime.activateAt(driver, 2);
    try std.testing.expectEqual(ActivationMode.published_data_plane, restarted.mode);
    try std.testing.expectEqual(@as(u32, 2), driver.restart_generation);
    try std.testing.expectEqual(driver.restart_generation, restarted.activation_generation);

    var readback = @as([storage_volume.sector_size]u8, @splat(0));
    try std.testing.expect(bootstrap_driver_port.activeStorageRead(service_id, 4, readback[0..]));
    try std.testing.expect(std.mem.eql(u8, before_restart[0..], readback[0..]));

    var after_restart = @as([storage_volume.sector_size]u8, @splat(0x55));
    const after_label = "after-restart";
    @memcpy(after_restart[0..after_label.len], after_label);
    try std.testing.expect(bootstrap_driver_port.activeStorageWrite(service_id, 4, after_restart[0..]));
    @memset(readback[0..], 0);
    try std.testing.expect(bootstrap_driver_port.activeStorageRead(service_id, 4, readback[0..]));
    try std.testing.expect(std.mem.eql(u8, after_restart[0..], readback[0..]));
}

test "runtime deactivates only the requested driver class for shared services" {
    if (!bootstrap_driver_port.reset()) @panic("storage lifecycle transition was refused");
    defer if (!bootstrap_driver_port.reset()) @panic("storage lifecycle transition was refused");

    const service_id: u64 = 91;
    const graphics_device_id: u64 = 0x1234_1111_0091;
    const input_device_id: u64 = 0x1234_2222_0091;
    try std.testing.expect(try bootstrap_driver_port.publishDeviceDataPlane(
        .graphics_adapter,
        graphics_device_id,
        "zigos.system.compositor",
        false,
    ));
    try std.testing.expect(try bootstrap_driver_port.publishDeviceDataPlane(
        .input_device,
        input_device_id,
        "zigos.system.compositor",
        false,
    ));
    try std.testing.expect(bootstrap_driver_port.activePublicationPublisher(
        .graphics_adapter,
        graphics_device_id,
        0,
    ) == null);

    const graphics_driver = driver_service.DriverRecord{
        .service_id = service_id,
        .owner_task_id = 191,
        .device_id = graphics_device_id,
        .device_class = .graphics_adapter,
        .authority_capability_id = 291,
        .restart_generation = 1,
        .bootstrap_transport = .none,
        .dma_domain_id = 391,
        .signer_fingerprint = @as([driver_service.SIGNER_FINGERPRINT_BYTES]u8, @splat(0)),
    };
    const input_driver = driver_service.DriverRecord{
        .service_id = service_id,
        .owner_task_id = 191,
        .device_id = input_device_id,
        .device_class = .input_device,
        .authority_capability_id = 292,
        .restart_generation = 1,
        .bootstrap_transport = .none,
        .dma_domain_id = 392,
        .signer_fingerprint = @as([driver_service.SIGNER_FINGERPRINT_BYTES]u8, @splat(0)),
    };

    var runtime = Runtime.init();
    const graphics_activation = try runtime.activateAt(&graphics_driver, 10);
    const input_activation = try runtime.activateAt(&input_driver, 11);
    try std.testing.expectEqual(ActivationMode.published_data_plane, graphics_activation.mode);
    try std.testing.expectEqual(ActivationMode.published_data_plane, input_activation.mode);
    try std.testing.expectEqual(graphics_driver.restart_generation, graphics_activation.activation_generation);
    try std.testing.expectEqual(input_driver.restart_generation, input_activation.activation_generation);
    try std.testing.expectEqualStrings("zigos.system.compositor", graphics_activation.publisherSlice());
    try std.testing.expectEqualStrings("zigos.system.compositor", input_activation.publisherSlice());
    try std.testing.expectEqual(service_id, bootstrap_driver_port.deviceDataPlanePublication(.graphics_adapter).?.active_service_id);
    try std.testing.expectEqual(service_id, bootstrap_driver_port.deviceDataPlanePublication(.input_device).?.active_service_id);

    try std.testing.expect(runtime.deactivateDriver(service_id, .graphics_adapter));
    try std.testing.expectEqual(@as(u64, 0), bootstrap_driver_port.deviceDataPlanePublication(.graphics_adapter).?.active_service_id);
    try std.testing.expectEqual(service_id, bootstrap_driver_port.deviceDataPlanePublication(.input_device).?.active_service_id);
    try std.testing.expectEqual(ActivationMode.control_only, runtime.findByClass(.graphics_adapter).?.mode);
    try std.testing.expectEqualStrings("", runtime.findByClass(.graphics_adapter).?.publisherSlice());
    try std.testing.expectEqual(ActivationMode.published_data_plane, runtime.findByClass(.input_device).?.mode);
    try std.testing.expect(runtime.findByClass(.input_device).?.hasExclusiveClaim());

    try std.testing.expect(!runtime.deactivateDriver(0xFFFF, .input_device));
    try std.testing.expect(runtime.deactivateDriver(service_id, .input_device));
    try std.testing.expectEqual(@as(u64, 0), bootstrap_driver_port.deviceDataPlanePublication(.graphics_adapter).?.active_service_id);
    try std.testing.expectEqual(@as(u64, 0), bootstrap_driver_port.deviceDataPlanePublication(.input_device).?.active_service_id);
    try std.testing.expectEqual(ActivationMode.control_only, runtime.findByClass(.graphics_adapter).?.mode);
    try std.testing.expectEqual(ActivationMode.control_only, runtime.findByClass(.input_device).?.mode);
}
