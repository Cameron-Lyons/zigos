const std = @import("std");
const bootstrap_driver_port = @import("bootstrap_driver_port.zig");
const driver_service = @import("driver_service.zig");
const component_port = @import("../kernel_api/component_port.zig");
const storage_volume = @import("../storage/storage_volume.zig");
const native_util = @import("../core/util.zig");
const copyText = native_util.copyText;

pub const MAX_ACTIVATIONS: usize = 8;

pub const ActivationMode = enum(u8) {
    control_only,
    published_data_plane,
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
};

const ActivationSlot = struct {
    in_use: bool = false,
    activation: ActivationRecord = zeroActivation(),
};

pub const Runtime = struct {
    kernel_port: ?*component_port.KernelPort = null,
    next_activation_generation: u32 = 1,
    slots: [MAX_ACTIVATIONS]ActivationSlot = [_]ActivationSlot{ActivationSlot{}} ** MAX_ACTIVATIONS,

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
                        if (publication.kernel_bootstrap and driver.bootstrap_transport != .kernel_published_data_plane) {
                            return error.KernelBootstrapNotAuthorized;
                        }
                        if (bootstrap_driver_port.activateNetworkDevice(driver.device_id, driver.service_id)) {
                            record.mode = .published_data_plane;
                            record.exclusive_claim = true;
                            record.kernel_bootstrap = publication.kernel_bootstrap;
                            record.publisher_len = copyText(record.publisher[0..], publication.publisherSlice());
                        }
                    }
                }
            },
            .storage_controller => {
                if (bootstrap_driver_port.storagePublication()) |publication| {
                    if (publication.device_id == driver.device_id) {
                        if (publication.kernel_bootstrap and driver.bootstrap_transport != .kernel_published_data_plane) {
                            return error.KernelBootstrapNotAuthorized;
                        }
                        if (bootstrap_driver_port.activateStorageBackend(
                            driver.device_id,
                            driver.service_id,
                            driver.authority_capability_id,
                            driver.owner_task_id,
                            now_ticks,
                            self.kernel_port,
                        )) {
                            record.mode = .published_data_plane;
                            record.exclusive_claim = true;
                            record.kernel_bootstrap = publication.kernel_bootstrap;
                            record.publisher_len = copyText(record.publisher[0..], publication.publisherSlice());
                        }
                    }
                }
            },
            else => {},
        }

        record.activation_generation = self.nextActivationGeneration();
        return self.upsert(record);
    }

    pub fn activate(self: *Runtime, driver: *const driver_service.DriverRecord) Error!ActivationRecord {
        return self.activateAt(driver, 0);
    }

    pub fn findByClass(self: *const Runtime, device_class: driver_service.DeviceClass) ?ActivationRecord {
        for (self.slots) |slot| {
            if (slot.in_use and slot.activation.device_class == device_class) return slot.activation;
        }
        return null;
    }

    pub fn deactivate(self: *Runtime, service_id: u64) bool {
        for (&self.slots) |*slot| {
            if (!slot.in_use or slot.activation.service_id != service_id) continue;
            if (slot.activation.mode == .published_data_plane and slot.activation.exclusive_claim) {
                const released = switch (slot.activation.device_class) {
                    .network_adapter => bootstrap_driver_port.deactivateNetworkDevice(service_id),
                    .storage_controller => bootstrap_driver_port.deactivateStorageBackend(service_id),
                    else => true,
                };
                if (!released) return false;
            }
            slot.activation.mode = .control_only;
            slot.activation.exclusive_claim = false;
            return true;
        }
        return false;
    }

    fn upsert(self: *Runtime, activation: ActivationRecord) Error!ActivationRecord {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.activation.service_id == activation.service_id) {
                slot.activation = activation;
                return slot.activation;
            }
        }

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.activation = activation;
            return slot.activation;
        }

        return error.ActivationTableFull;
    }

    fn nextActivationGeneration(self: *Runtime) u32 {
        defer self.next_activation_generation += 1;
        return self.next_activation_generation;
    }
};

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

test "runtime refuses kernel-published transports for drivers without bootstrap authorization" {
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

    try std.testing.expect(bootstrap_driver_port.publishNetworkActivator(
        0x8086_100E_0001,
        "e1000",
        FakeNetworkDevice.activate,
        true,
    ));

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
    try std.testing.expectError(error.KernelBootstrapNotAuthorized, runtime.activateAt(driver, 1));
}

test "runtime uses the activation tick when claiming storage bootstrap authority" {
    const capability = @import("../kernel_api/capability.zig");
    const device_broker = @import("../kernel_api/device_broker.zig");
    const endpoint = @import("../kernel_api/endpoint.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const principal = @import("../core/principal.zig");
    const shared_memory = @import("../kernel_api/shared_memory.zig");
    const task_runtime = @import("../task/task_runtime.zig");

    const device_id: u64 = 0x0000_1F00_0001;

    bootstrap_driver_port.reset();
    defer bootstrap_driver_port.reset();
    device_broker.reset();
    defer device_broker.reset();
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

    try std.testing.expect(device_broker.publishAtaController(device_id, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = storage_volume.required_device_sectors,
    }));
    try std.testing.expect(bootstrap_driver_port.publishStorageAtaBootstrap(
        device_id,
        "ata-bootstrap",
        true,
    ));

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
        .bootstrap_transport = .kernel_published_data_plane,
    });

    var driver_runtime = Runtime.init();
    driver_runtime.bindKernelPort(&kernel_port);
    const activation = try driver_runtime.activateAt(driver, 10);
    try std.testing.expectEqual(ActivationMode.control_only, activation.mode);
    try std.testing.expect(!storage_volume.hasAttachedDevice());
}
