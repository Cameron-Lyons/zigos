const std = @import("std");
const builtin = @import("builtin");
const bootstrap_driver_port = @import("bootstrap_driver_port.zig");
const driver_service = @import("driver_service.zig");
const component_port = @import("../kernel_api/component_port.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const root = @import("root");
const storage_volume = if (builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume"))
    root.storage_volume
else
    @import("../storage/storage_volume.zig");
const native_util = @import("../core/util.zig");

pub const MAX_ACTIVATIONS: usize = 8;
const SERVICE_INDEX_CAPACITY: usize = MAX_ACTIVATIONS * 2;

pub const ActivationMode = enum(u8) {
    control_only,
    published_data_plane,
    userspace_brokered_data_plane,
};

pub const ActivationRecord = struct {
    service_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
    dma_domain_id: u64,
    iommu_enforced: bool,
    mode: ActivationMode,
    exclusive_claim: bool,
    activation_generation: u32,
    kernel_bootstrap: bool,
    publisher_len: usize,
    publisher: [32]u8,

    pub fn publisherSlice(self: *const ActivationRecord) []const u8 {
        return self.publisher[0..self.publisher_len];
    }
};

pub const Error = error{
    ActivationTableFull,
    KernelBootstrapNotAuthorized,
    MissingDmaDomain,
    PublisherTooLong,
};

const ActivationSlot = struct {
    in_use: bool = false,
    activation: ActivationRecord = zeroActivation(),
};

const ActivationArena = indexed_arena.IndexedArena(ActivationSlot, MAX_ACTIVATIONS, SERVICE_INDEX_CAPACITY, activationSlotKey);
const ActivationClassIndex = indexed_arena.UniqueIndex(SERVICE_INDEX_CAPACITY);

pub const Runtime = struct {
    kernel_port: ?*component_port.KernelPort = null,
    next_activation_generation: u32 = 1,
    arena: ActivationArena = ActivationArena.init(),
    class_index: ActivationClassIndex = ActivationClassIndex.init(),

    pub fn init() Runtime {
        return .{};
    }

    pub fn bindKernelPort(self: *Runtime, kernel_port: *component_port.KernelPort) void {
        self.kernel_port = kernel_port;
    }

    pub fn activateAt(
        self: *Runtime,
        driver: *const driver_service.DriverRecord,
        now_ticks: u64,
    ) Error!ActivationRecord {
        return self.activateRecordAt(driver, now_ticks);
    }

    pub fn activateModeAt(
        self: *Runtime,
        driver: *const driver_service.DriverRecord,
        now_ticks: u64,
    ) Error!ActivationMode {
        const record = try self.activateRecordAt(driver, now_ticks);
        return record.mode;
    }

    fn activateRecordAt(
        self: *Runtime,
        driver: *const driver_service.DriverRecord,
        now_ticks: u64,
    ) Error!ActivationRecord {
        var record = ActivationRecord{
            .service_id = driver.service_id,
            .device_id = driver.device_id,
            .device_class = driver.device_class,
            .dma_domain_id = driver.dma_domain_id,
            .iommu_enforced = driver.dma_protection == .iommu_enforced,
            .mode = .control_only,
            .exclusive_claim = false,
            .activation_generation = 0,
            .kernel_bootstrap = false,
            .publisher_len = 0,
            .publisher = [_]u8{0} ** 32,
        };
        if (record.dma_domain_id == 0 or !record.iommu_enforced) return error.MissingDmaDomain;

        switch (driver.device_class) {
            .network_adapter => {
                if (bootstrap_driver_port.networkPublication()) |publication| {
                    if (publication.device_id == driver.device_id) {
                        if (publication.kernel_bootstrap and driver.bootstrap_transport != .kernel_bootstrap_broker) {
                            return error.KernelBootstrapNotAuthorized;
                        }
                        if (bootstrap_driver_port.activateNetworkDevice(driver.device_id, driver.service_id)) {
                            record.mode = .published_data_plane;
                            record.exclusive_claim = true;
                            record.kernel_bootstrap = publication.kernel_bootstrap;
                            record.publisher_len = native_util.copyTextExact(record.publisher[0..], publication.publisherSlice()) catch return error.PublisherTooLong;
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
                            record.mode = if (publication.kind == .ata_bootstrap_bridge)
                                .userspace_brokered_data_plane
                            else
                                .published_data_plane;
                            record.exclusive_claim = true;
                            record.kernel_bootstrap = publication.kernel_bootstrap;
                            record.publisher_len = native_util.copyTextExact(record.publisher[0..], publication.publisherSlice()) catch return error.PublisherTooLong;
                        }
                    }
                }
            },
            .graphics_adapter, .audio_print_io, .input_device => {
                if (bootstrap_driver_port.deviceDataPlanePublication(driver.device_class)) |publication| {
                    if (publication.device_id == driver.device_id) {
                        if (publication.kernel_bootstrap) return error.KernelBootstrapNotAuthorized;
                        if (bootstrap_driver_port.activateDeviceDataPlane(driver.device_class, driver.device_id, driver.service_id)) {
                            record.mode = .published_data_plane;
                            record.exclusive_claim = true;
                            record.kernel_bootstrap = false;
                            record.publisher_len = native_util.copyTextExact(record.publisher[0..], publication.publisherSlice()) catch return error.PublisherTooLong;
                        }
                    }
                }
            },
        }

        record.activation_generation = self.nextActivationGeneration();
        return self.upsert(record);
    }

    pub fn activate(self: *Runtime, driver: *const driver_service.DriverRecord) Error!ActivationRecord {
        return self.activateAt(driver, 0);
    }

    pub fn findByClass(self: *const Runtime, device_class: driver_service.DeviceClass) ?ActivationRecord {
        const slot_index = self.class_index.lookup(deviceClassKey(device_class)) orelse return null;
        if (slot_index >= MAX_ACTIVATIONS) return null;
        const slot = self.arena.slots[slot_index];
        if (!slot.in_use or slot.activation.device_class != device_class) return null;
        return slot.activation;
    }

    pub fn deactivate(self: *Runtime, service_id: u64) bool {
        var deactivated_any = false;
        for (&self.arena.slots) |*slot| {
            if (!slot.in_use or slot.activation.service_id != service_id) continue;
            if (!self.deactivateSlot(slot)) return false;
            deactivated_any = true;
        }
        return deactivated_any;
    }

    pub fn deactivateDriver(self: *Runtime, service_id: u64, device_class: driver_service.DeviceClass) bool {
        const slot = self.findByServiceClassSlot(service_id, device_class) orelse return false;
        return self.deactivateSlot(slot);
    }

    fn deactivateSlot(self: *Runtime, slot: *ActivationSlot) bool {
        _ = self;
        if (slot.activation.mode != .control_only and slot.activation.exclusive_claim) {
            const released = switch (slot.activation.device_class) {
                .network_adapter => bootstrap_driver_port.deactivateNetworkDevice(slot.activation.service_id),
                .storage_controller => bootstrap_driver_port.deactivateStorageBackend(slot.activation.service_id),
                .graphics_adapter, .audio_print_io, .input_device => bootstrap_driver_port.deactivateDeviceDataPlane(slot.activation.device_class, slot.activation.service_id),
            };
            if (!released) return false;
        }
        slot.activation.mode = .control_only;
        slot.activation.exclusive_claim = false;
        return true;
    }

    fn upsert(self: *Runtime, activation: ActivationRecord) Error!ActivationRecord {
        if (self.findByServiceClassSlot(activation.service_id, activation.device_class)) |slot| {
            self.class_index.remove(deviceClassKey(slot.activation.device_class));
            slot.activation = activation;
            const slot_index = self.arena.slotIndexOf(activationKeyFor(activation.service_id, activation.device_class)).?;
            self.class_index.insert(deviceClassKey(activation.device_class), slot_index);
            return slot.activation;
        }

        const slot_index = self.arena.reserveIndex(activationKeyFor(activation.service_id, activation.device_class)) orelse return error.ActivationTableFull;
        const slot = &self.arena.slots[slot_index];
        slot.activation = activation;
        self.class_index.insert(deviceClassKey(activation.device_class), slot_index);
        return slot.activation;
    }

    fn findByServiceSlot(self: *Runtime, service_id: u64) ?*ActivationSlot {
        for (&self.arena.slots) |*slot| {
            if (slot.in_use and slot.activation.service_id == service_id) return slot;
        }
        return null;
    }

    fn findByServiceClassSlot(self: *Runtime, service_id: u64, device_class: driver_service.DeviceClass) ?*ActivationSlot {
        return self.arena.get(activationKeyFor(service_id, device_class));
    }

    fn nextActivationGeneration(self: *Runtime) u32 {
        defer self.next_activation_generation += 1;
        return self.next_activation_generation;
    }
};

fn activationSlotKey(slot: *const ActivationSlot) u64 {
    return activationKeyFor(slot.activation.service_id, slot.activation.device_class);
}

fn activationKeyFor(service_id: u64, device_class: driver_service.DeviceClass) u64 {
    return service_id *% 16 + deviceClassKey(device_class);
}

fn deviceClassKey(device_class: driver_service.DeviceClass) u64 {
    return @as(u64, @intFromEnum(device_class)) + 1;
}

fn zeroActivation() ActivationRecord {
    return .{
        .service_id = 0,
        .device_id = 0,
        .device_class = .network_adapter,
        .dma_domain_id = 0,
        .iommu_enforced = false,
        .mode = .control_only,
        .exclusive_claim = false,
        .activation_generation = 0,
        .kernel_bootstrap = false,
        .publisher_len = 0,
        .publisher = [_]u8{0} ** 32,
    };
}

test "kernel bootstrap cannot publish network data-plane transports" {
    const FakeNetworkDevice = struct {
        fn send(_: []const u8) void {}

        fn getMacAddress() [6]u8 {
            return .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
        }

        const device = bootstrap_driver_port.NetworkDevice{
            .send = send,
            .getMacAddress = getMacAddress,
        };

        fn activate(device_id: u64) ?*const bootstrap_driver_port.NetworkDevice {
            if (device_id != 0x8086_100E_0001) return null;
            return &device;
        }
    };

    bootstrap_driver_port.reset();
    defer bootstrap_driver_port.reset();

    try std.testing.expect(!(try bootstrap_driver_port.publishNetworkActivator(
        0x8086_100E_0001,
        "e1000",
        FakeNetworkDevice.activate,
        true,
    )));

    var directory = driver_service.Directory.init();
    const capability = @import("../kernel_api/capability.zig");
    var capabilities = capability.CapabilityTable.init();
    const driver_authority = try capabilities.mintBootRoot(.{
        .holder = .{ .kind = .service, .serial = 91 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = driver_service.authorityTarget(0x8086_100E_0001),
        .rights = driver_service.allowedRightsFor(.network_adapter),
        .scope = .{
            .task_id = 901,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{},
    });
    const driver = try directory.register(.{
        .service_id = 91,
        .owner_task_id = 901,
        .device_id = 0x8086_100E_0001,
        .device_class = .network_adapter,
        .authority_capability_id = driver_authority.id,
        .capability_table = &capabilities,
        .requester = driver_authority.holder,
        .now_ticks = 1,
        .bundle = .{
            .bundle_id = "svc.driver.net",
            .display_name = "Network Driver",
            .publisher = "zigos.spec",
            .signature = .{
                .format = "ed25519",
                .signer = "zigos-spec-driver",
            },
        },
    });

    var runtime = Runtime.init();
    const activation = try runtime.activateAt(driver, 1);
    try std.testing.expectEqual(ActivationMode.control_only, activation.mode);
    try std.testing.expect(!activation.exclusive_claim);
}

test "runtime uses the activation tick when claiming storage bootstrap authority" {
    const capability = @import("../kernel_api/capability.zig");
    const device_broker = @import("../kernel_api/device_broker.zig");
    const endpoint = @import("../kernel_api/endpoint.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const principal = @import("../core/principal.zig");
    const shared_memory = @import("../kernel_api/shared_memory.zig");
    const task_runtime = @import("../task/task_runtime.zig");
    const device_inventory = @import("device_inventory.zig");

    const device_id: u64 = 0x0000_1F00_0001;

    bootstrap_driver_port.reset();
    defer bootstrap_driver_port.reset();
    device_broker.reset();
    defer device_broker.reset();
    device_inventory.reset();
    defer device_inventory.reset();
    storage_volume.clearAttachedBackend();
    defer storage_volume.clearAttachedBackend();

    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = native_kernel.Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    var kernel_port = component_port.KernelPort.init(&kernel);

    device_inventory.registerDetected(.storage_controller, device_id, .ata_bootstrap, true);
    device_inventory.recordAtaBootstrapGrant(device_id, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = storage_volume.required_device_sectors,
    });

    const storage_driver_lease_image = task_runtime.syntheticUserspaceImage(
        "storage-driver-lease-test",
        "zigos.system.storage-driver",
    );
    const driver_task = try runtime.createTask(.{
        .owner = principal.PrincipalId{ .kind = .service, .serial = 30 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 30,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.storage-driver",
        },
        .userspace_image = &storage_driver_lease_image,
    });
    const device_capability = try capabilities.mintBootRoot(.{
        .holder = driver_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .device, .id = device_id },
        .rights = driver_service.allowedRightsFor(.storage_controller),
        .scope = .{
            .task_id = driver_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 1,
            .expires_at_ticks = 5,
            .renewable = false,
        },
        .audit = .{},
    });
    try runtime.grantCapability(driver_task.id, device_capability.id);

    var directory = driver_service.Directory.init();
    const driver = try directory.register(.{
        .service_id = 30,
        .owner_task_id = driver_task.id,
        .device_id = device_id,
        .device_class = .storage_controller,
        .authority_capability_id = device_capability.id,
        .capability_table = &capabilities,
        .requester = driver_task.owner,
        .now_ticks = 2,
        .bundle = .{
            .bundle_id = "svc.driver.storage-runtime",
            .display_name = "Storage Driver Runtime",
            .publisher = "zigos.spec",
            .signature = .{
                .format = "ed25519",
                .signer = "zigos-spec-driver",
            },
        },
        .bootstrap_transport = .kernel_bootstrap_broker,
    });
    try std.testing.expect(try bootstrap_driver_port.claimStorageAtaBootstrapInventory(driver, "zigos.system.storage-driver"));

    var driver_runtime = Runtime.init();
    driver_runtime.bindKernelPort(&kernel_port);
    const activation = try driver_runtime.activateAt(driver, 10);
    try std.testing.expectEqual(ActivationMode.control_only, activation.mode);
    try std.testing.expect(!storage_volume.hasAttachedDevice());
}

test "runtime deactivates only the requested driver class for shared services" {
    bootstrap_driver_port.reset();
    defer bootstrap_driver_port.reset();

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

    const empty_dma_ranges = [_]driver_service.DmaRange{.{ .base = 0, .length = 0 }} ** driver_service.MAX_DMA_RANGES;
    const graphics_driver = driver_service.DriverRecord{
        .service_id = service_id,
        .owner_task_id = 191,
        .device_id = graphics_device_id,
        .device_class = .graphics_adapter,
        .authority_capability_id = 291,
        .restart_generation = 1,
        .bootstrap_transport = .none,
        .dma_domain_id = 391,
        .dma_protection = .iommu_enforced,
        .dma_range_count = 0,
        .dma_ranges = empty_dma_ranges,
        .signer_len = 0,
        .signer = [_]u8{0} ** 32,
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
        .dma_protection = .iommu_enforced,
        .dma_range_count = 0,
        .dma_ranges = empty_dma_ranges,
        .signer_len = 0,
        .signer = [_]u8{0} ** 32,
    };

    var runtime = Runtime.init();
    const graphics_activation = try runtime.activateAt(&graphics_driver, 10);
    const input_activation = try runtime.activateAt(&input_driver, 11);
    try std.testing.expectEqual(ActivationMode.published_data_plane, graphics_activation.mode);
    try std.testing.expectEqual(ActivationMode.published_data_plane, input_activation.mode);
    try std.testing.expectEqual(service_id, bootstrap_driver_port.deviceDataPlanePublication(.graphics_adapter).?.active_service_id);
    try std.testing.expectEqual(service_id, bootstrap_driver_port.deviceDataPlanePublication(.input_device).?.active_service_id);

    try std.testing.expect(runtime.deactivateDriver(service_id, .graphics_adapter));
    try std.testing.expectEqual(@as(u64, 0), bootstrap_driver_port.deviceDataPlanePublication(.graphics_adapter).?.active_service_id);
    try std.testing.expectEqual(service_id, bootstrap_driver_port.deviceDataPlanePublication(.input_device).?.active_service_id);
    try std.testing.expectEqual(ActivationMode.control_only, runtime.findByClass(.graphics_adapter).?.mode);
    try std.testing.expectEqual(ActivationMode.published_data_plane, runtime.findByClass(.input_device).?.mode);
    try std.testing.expect(runtime.findByClass(.input_device).?.exclusive_claim);
}
