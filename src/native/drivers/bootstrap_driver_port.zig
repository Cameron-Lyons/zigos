const std = @import("std");
const builtin = @import("builtin");
const native_util = @import("../core/util.zig");
const component_port = @import("../kernel_api/component_port.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const device_inventory = @import("device_inventory.zig");
const driver_service = @import("driver_service.zig");
const network_driver_task = @import("network_driver_task.zig");
const storage_driver_task = @import("storage_driver_task.zig");
const root = @import("root");
const kernel_network_claim = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/net/link_port.zig")
else
    struct {
        pub fn init() void {}
        pub fn recordDriverClaim(_: u64, _: u64) bool {
            return true;
        }
        pub fn clearDriverClaim(_: u64) bool {
            return true;
        }
    };
const storage_volume = if (builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume"))
    root.storage_volume
else
    @import("../storage/storage_volume.zig");

pub const NetworkDevice = network_driver_task.NetworkDevice;
pub const EgressRequest = network_driver_task.EgressRequest;
pub const EgressDecision = network_driver_task.EgressDecision;
pub const EgressBroker = network_driver_task.EgressBroker;
pub const NetworkActivator = *const fn (device_id: u64) ?*const NetworkDevice;
pub const StorageActivator = *const fn (device_id: u64) ?storage_volume.Backend;

pub const StoragePublicationKind = enum(u8) {
    backend,
    activator,
    ata_bootstrap_bridge,
};

pub const DeviceDataPlanePublication = struct {
    device_class: driver_service.DeviceClass = .graphics_adapter,
    device_id: u64,
    publisher_len: usize = 0,
    publisher: [32]u8 = [_]u8{0} ** 32,
    kernel_bootstrap: bool = true,
    active_service_id: u64 = 0,

    pub fn publisherSlice(self: *const DeviceDataPlanePublication) []const u8 {
        return self.publisher[0..self.publisher_len];
    }
};

pub const Error = error{
    PublisherTooLong,
};

pub const NetworkPublication = struct {
    device_id: u64,
    publisher_len: usize = 0,
    publisher: [32]u8 = [_]u8{0} ** 32,
    network_device: ?*const NetworkDevice = null,
    activator: ?NetworkActivator = null,
    kernel_bootstrap: bool = true,
    active_service_id: u64 = 0,

    pub fn publisherSlice(self: *const NetworkPublication) []const u8 {
        return self.publisher[0..self.publisher_len];
    }
};

pub const StoragePublication = struct {
    device_id: u64,
    publisher_len: usize = 0,
    publisher: [32]u8 = [_]u8{0} ** 32,
    backend: ?storage_volume.Backend = null,
    ata_session: ?storage_driver_task.AtaControllerSession = null,
    activator: ?StorageActivator = null,
    kind: StoragePublicationKind = .backend,
    kernel_bootstrap: bool = true,
    active_service_id: u64 = 0,

    pub fn publisherSlice(self: *const StoragePublication) []const u8 {
        return self.publisher[0..self.publisher_len];
    }
};

var published_network: ?NetworkPublication = null;
var published_storage: ?StoragePublication = null;
var published_device_planes = [_]?DeviceDataPlanePublication{null} ** device_class_count;

pub fn reset() void {
    published_network = null;
    published_storage = null;
    published_device_planes = [_]?DeviceDataPlanePublication{null} ** device_class_count;
    device_broker.reset();
    kernel_network_claim.init();
    network_driver_task.reset();
    storage_volume.clearAttachedBackend();
}

pub fn publishNetworkDevice(
    device_id: u64,
    publisher: []const u8,
    network_device: *const NetworkDevice,
    kernel_bootstrap: bool,
) Error!bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(NetworkPublication, published_network, device_id)) return false;
    var publication = try initPublication(NetworkPublication, device_id, publisher, kernel_bootstrap);
    publication.network_device = network_device;
    published_network = publication;
    return true;
}

pub fn publishNetworkActivator(
    device_id: u64,
    publisher: []const u8,
    activator: NetworkActivator,
    kernel_bootstrap: bool,
) Error!bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(NetworkPublication, published_network, device_id)) return false;
    var publication = try initPublication(NetworkPublication, device_id, publisher, kernel_bootstrap);
    publication.activator = activator;
    published_network = publication;
    return true;
}

pub fn publishStorageBackend(
    device_id: u64,
    publisher: []const u8,
    backend: storage_volume.Backend,
    kernel_bootstrap: bool,
) Error!bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(StoragePublication, published_storage, device_id)) return false;
    var publication = try initPublication(StoragePublication, device_id, publisher, kernel_bootstrap);
    publication.backend = backend;
    publication.kind = .backend;
    published_storage = publication;
    return true;
}

pub fn publishStorageActivator(
    device_id: u64,
    publisher: []const u8,
    activator: StorageActivator,
    kernel_bootstrap: bool,
) Error!bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(StoragePublication, published_storage, device_id)) return false;
    var publication = try initPublication(StoragePublication, device_id, publisher, kernel_bootstrap);
    publication.activator = activator;
    publication.kind = .activator;
    published_storage = publication;
    return true;
}

pub fn publishStorageAtaBootstrap(
    device_id: u64,
    publisher: []const u8,
    kernel_bootstrap: bool,
) Error!bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(StoragePublication, published_storage, device_id)) return false;
    var publication = try initPublication(StoragePublication, device_id, publisher, kernel_bootstrap);
    publication.kind = .ata_bootstrap_bridge;
    published_storage = publication;
    return true;
}

pub fn publishDeviceDataPlane(
    device_class: driver_service.DeviceClass,
    device_id: u64,
    publisher: []const u8,
    kernel_bootstrap: bool,
) Error!bool {
    if (kernel_bootstrap) return false;
    if (!supportsGenericDeviceDataPlane(device_class)) return false;
    const index = deviceClassIndex(device_class);
    if (!canPublishPublication(DeviceDataPlanePublication, published_device_planes[index], device_id)) return false;
    var publication = try initPublication(DeviceDataPlanePublication, device_id, publisher, kernel_bootstrap);
    publication.device_class = device_class;
    published_device_planes[index] = publication;
    return true;
}

pub fn claimStorageAtaBootstrapInventory(driver: *const driver_service.DriverRecord, publisher: []const u8) Error!bool {
    if (driver.device_class != .storage_controller) return false;
    if (driver.bootstrap_transport != .kernel_bootstrap_broker) return false;

    const inventory = device_inventory.recordForClass(.storage_controller);
    if (!inventory.detected or inventory.device_id != driver.device_id) return false;
    if (inventory.source != .ata_bootstrap or !inventory.kernel_bootstrap) return false;

    const grant = device_inventory.ataBootstrapGrant(driver.device_id) orelse return false;
    if (!device_broker.publishAtaController(driver.device_id, grant)) return false;
    return publishStorageAtaBootstrap(driver.device_id, publisher, false);
}

pub fn networkPublication() ?NetworkPublication {
    return published_network;
}

pub fn storagePublication() ?StoragePublication {
    return published_storage;
}

pub fn deviceDataPlanePublication(device_class: driver_service.DeviceClass) ?DeviceDataPlanePublication {
    if (!supportsGenericDeviceDataPlane(device_class)) return null;
    return published_device_planes[deviceClassIndex(device_class)];
}

pub fn hasActiveNetworkDevice() bool {
    return network_driver_task.hasActiveDevice();
}

pub fn setEgressBroker(broker: ?EgressBroker) void {
    network_driver_task.setEgressBroker(broker);
}

pub fn bindEgressCapability(capability_id: u64, policy_id: u64) void {
    network_driver_task.bindEgressCapability(capability_id, policy_id);
}

pub fn clearEgressCapability() void {
    network_driver_task.clearEgressCapability();
}

pub fn authorizeDriverTx(frame: []const u8) bool {
    return network_driver_task.authorizeDriverTx(frame);
}

pub fn sendActiveNetworkFrame(frame: []const u8) bool {
    return network_driver_task.sendActiveFrame(frame);
}

pub fn activateNetworkDevice(device_id: u64, service_id: u64) bool {
    if (publicationForActivation(NetworkPublication, &published_network, device_id, service_id)) |publication| {
        if (publication.network_device == null) {
            const activator = publication.activator orelse return false;
            publication.network_device = activator(device_id) orelse return false;
        }
        if (!kernel_network_claim.recordDriverClaim(device_id, service_id)) return false;
        if (!network_driver_task.activateDevice(publication.network_device.?, service_id)) return false;
        publication.active_service_id = service_id;
        return true;
    }
    return false;
}

pub fn activateDeviceDataPlane(device_class: driver_service.DeviceClass, device_id: u64, service_id: u64) bool {
    if (!supportsGenericDeviceDataPlane(device_class)) return false;
    if (publicationForActivation(DeviceDataPlanePublication, &published_device_planes[deviceClassIndex(device_class)], device_id, service_id)) |publication| {
        if (publication.device_class != device_class) return false;
        publication.active_service_id = service_id;
        return true;
    }
    return false;
}

pub fn activateStorageBackend(
    device_id: u64,
    service_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    dma_domain_id: u64,
    now_ticks: u64,
    kernel_port: ?*component_port.KernelPort,
) bool {
    if (publicationForActivation(StoragePublication, &published_storage, device_id, service_id)) |publication| {
        switch (publication.kind) {
            .ata_bootstrap_bridge => {
                const bound_kernel_port = kernel_port orelse return false;
                if (publication.ata_session == null) {
                    _ = device_broker.programBrokeredDmaIsolation(device_id, dma_domain_id) catch return false;
                    publication.ata_session = storage_driver_task.establishAtaBootstrapSession(
                        bound_kernel_port,
                        device_id,
                        authority_capability_id,
                        owner_task_id,
                        dma_domain_id,
                        now_ticks,
                    ) orelse return false;
                }
                if (publication.ata_session) |*session| {
                    storage_driver_task.attachAtaBootstrapSession(session);
                } else {
                    return false;
                }
            },
            .backend, .activator => {
                if (publication.backend == null) {
                    const activator = publication.activator orelse return false;
                    publication.backend = activator(device_id) orelse return false;
                }
                storage_volume.attachBackend(publication.backend.?);
            },
        }
        publication.active_service_id = service_id;
        return true;
    }
    return false;
}

pub fn deactivateNetworkDevice(service_id: u64) bool {
    if (publicationForDeactivation(NetworkPublication, &published_network, service_id)) |publication| {
        publication.active_service_id = 0;
        _ = network_driver_task.deactivateDevice(service_id);
        _ = kernel_network_claim.clearDriverClaim(service_id);
        return true;
    }
    return false;
}

pub fn deactivateStorageBackend(service_id: u64) bool {
    if (publicationForDeactivation(StoragePublication, &published_storage, service_id)) |publication| {
        publication.active_service_id = 0;
        publication.ata_session = null;
        storage_volume.clearAttachedBackend();
        return true;
    }
    return false;
}

pub fn activeStorageRead(service_id: u64, start_lba: u64, buffer: []u8) bool {
    const publication = publicationForActiveStorage(service_id) orelse return false;
    return switch (publication.kind) {
        .ata_bootstrap_bridge => blk: {
            if (publication.ata_session) |*session| {
                break :blk storage_driver_task.readAtaBootstrapSession(session, start_lba, buffer);
            }
            break :blk false;
        },
        .backend, .activator => blk: {
            const backend = publication.backend orelse return false;
            break :blk backend.read(start_lba, buffer.ptr, buffer.len);
        },
    };
}

pub fn activeStorageWrite(service_id: u64, start_lba: u64, buffer: []const u8) bool {
    const publication = publicationForActiveStorage(service_id) orelse return false;
    return switch (publication.kind) {
        .ata_bootstrap_bridge => blk: {
            if (publication.ata_session) |*session| {
                break :blk storage_driver_task.writeAtaBootstrapSession(session, start_lba, buffer);
            }
            break :blk false;
        },
        .backend, .activator => blk: {
            const backend = publication.backend orelse return false;
            break :blk backend.write(start_lba, buffer.ptr, buffer.len);
        },
    };
}

pub fn activeBrokeredStorageRead(service_id: u64, start_lba: u64, buffer: []u8) bool {
    const publication = publicationForActiveStorage(service_id) orelse return false;
    if (publication.kind != .ata_bootstrap_bridge) return false;
    if (publication.ata_session) |*session| {
        return storage_driver_task.readAtaBootstrapSession(session, start_lba, buffer);
    }
    return false;
}

pub fn activeBrokeredStorageWrite(service_id: u64, start_lba: u64, buffer: []const u8) bool {
    const publication = publicationForActiveStorage(service_id) orelse return false;
    if (publication.kind != .ata_bootstrap_bridge) return false;
    if (publication.ata_session) |*session| {
        return storage_driver_task.writeAtaBootstrapSession(session, start_lba, buffer);
    }
    return false;
}

pub fn activeStorageAtaSession(service_id: u64) ?storage_driver_task.AtaControllerSession {
    const publication = publicationForActiveStorage(service_id) orelse return null;
    if (publication.kind != .ata_bootstrap_bridge) return null;
    return publication.ata_session;
}

pub fn deactivateDeviceDataPlane(device_class: driver_service.DeviceClass, service_id: u64) bool {
    if (!supportsGenericDeviceDataPlane(device_class)) return false;
    if (publicationForDeactivation(DeviceDataPlanePublication, &published_device_planes[deviceClassIndex(device_class)], service_id)) |publication| {
        if (publication.device_class != device_class) return false;
        publication.active_service_id = 0;
        return true;
    }
    return false;
}

fn canPublishPublication(comptime T: type, publication: ?T, device_id: u64) bool {
    if (publication) |existing| {
        return existing.device_id == device_id;
    }
    return true;
}

fn publicationForActivation(comptime T: type, publication: *?T, device_id: u64, service_id: u64) ?*T {
    if (publication.*) |*published| {
        if (published.device_id != device_id) return null;
        if (published.active_service_id != 0 and published.active_service_id != service_id) return null;
        return published;
    }
    return null;
}

fn publicationForDeactivation(comptime T: type, publication: *?T, service_id: u64) ?*T {
    if (publication.*) |*published| {
        if (published.active_service_id != service_id) return null;
        return published;
    }
    return null;
}

fn publicationForActiveStorage(service_id: u64) ?*StoragePublication {
    if (published_storage) |*publication| {
        if (publication.active_service_id == service_id) return publication;
    }
    return null;
}

fn initPublication(comptime T: type, device_id: u64, publisher: []const u8, kernel_bootstrap: bool) Error!T {
    var publication = T{
        .device_id = device_id,
        .kernel_bootstrap = kernel_bootstrap,
    };
    publication.publisher_len = native_util.copyTextExact(publication.publisher[0..], publisher) catch return error.PublisherTooLong;
    return publication;
}

fn supportsGenericDeviceDataPlane(device_class: driver_service.DeviceClass) bool {
    return switch (device_class) {
        .usb_controller,
        .graphics_adapter,
        .audio_print_io,
        .input_device,
        .compositor_policy,
        => true,
        .network_adapter, .storage_controller => false,
    };
}

const device_class_count = std.meta.fields(driver_service.DeviceClass).len;

fn deviceClassIndex(device_class: driver_service.DeviceClass) usize {
    return @intFromEnum(device_class);
}

test "driver-backed network tx fails closed without capability-backed egress decision" {
    if (builtin.target.os.tag == .freestanding) return error.SkipZigTest;

    reset();
    defer reset();

    const Harness = struct {
        var send_count: usize = 0;
        var saw_policy_id: u64 = 0;
        var saw_capability_id: u64 = 0;

        fn send(_: []const u8) void {
            send_count += 1;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 1 };
        }

        fn broker(request: EgressRequest) EgressDecision {
            saw_policy_id = request.network_policy_id;
            saw_capability_id = request.egress_capability_id;
            return .{
                .allowed = request.network_policy_id == 44 and request.egress_capability_id == 99,
                .capability_backed = request.egress_capability_id != 0,
            };
        }
    };

    const device = NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(try publishNetworkDevice(7001, "test-net", &device, false));
    try std.testing.expect(activateNetworkDevice(7001, 9));

    const frame_with_raw_destination = "GET / HTTP/1.1\r\nHost: relay.zigos.dev\r\nX-IP: 203.0.113.7\r\n\r\n";
    try std.testing.expect(!sendActiveNetworkFrame(frame_with_raw_destination));
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    setEgressBroker(Harness.broker);
    try std.testing.expect(!sendActiveNetworkFrame(frame_with_raw_destination));
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);
    try std.testing.expectEqual(@as(u64, 0), Harness.saw_capability_id);

    bindEgressCapability(99, 44);
    try std.testing.expect(sendActiveNetworkFrame(frame_with_raw_destination));
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
    try std.testing.expectEqual(@as(u64, 44), Harness.saw_policy_id);
    try std.testing.expectEqual(@as(u64, 99), Harness.saw_capability_id);
}

test "adversarial raw IP or domain knowledge cannot substitute for egress capability" {
    if (builtin.target.os.tag == .freestanding) return error.SkipZigTest;

    reset();
    defer reset();

    const Harness = struct {
        var send_count: usize = 0;

        fn send(_: []const u8) void {
            send_count += 1;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 2 };
        }

        fn adversarialBroker(request: EgressRequest) EgressDecision {
            const contains_known_ip = std.mem.indexOf(u8, request.frame, "203.0.113.7") != null;
            const contains_known_domain = std.mem.indexOf(u8, request.frame, "relay.zigos.dev") != null;
            return .{
                .allowed = contains_known_ip and contains_known_domain,
                .capability_backed = request.egress_capability_id == 31337 and request.network_policy_id == 5150,
            };
        }
    };

    const device = NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(try publishNetworkDevice(7002, "test-net", &device, false));
    try std.testing.expect(activateNetworkDevice(7002, 10));
    setEgressBroker(Harness.adversarialBroker);

    const forged_frame = "dst=203.0.113.7; host=relay.zigos.dev";
    try std.testing.expect(!sendActiveNetworkFrame(forged_frame));
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    bindEgressCapability(31337, 5150);
    try std.testing.expect(sendActiveNetworkFrame(forged_frame));
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
}

test "kernel bootstrap cannot publish storage data-plane transports directly" {
    if (builtin.target.os.tag == .freestanding) return error.SkipZigTest;

    reset();
    defer reset();

    const Backend = struct {
        fn read(_: u64, _: [*]u8, _: usize) callconv(.c) bool {
            return false;
        }

        fn write(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return false;
        }

        fn activate(_: u64) ?storage_volume.Backend {
            return null;
        }
    };

    const backend = storage_volume.Backend{
        .sector_count = 1,
        .read = Backend.read,
        .write = Backend.write,
    };

    try std.testing.expect(!(try publishStorageBackend(0x1F001, "kernel-storage", backend, true)));
    try std.testing.expect(!(try publishStorageActivator(0x1F001, "kernel-storage", Backend.activate, true)));
    try std.testing.expect(!(try publishStorageAtaBootstrap(0x1F001, "kernel-storage", true)));
    try std.testing.expect(storagePublication() == null);
}

test "kernel bootstrap cannot publish peripheral device data-plane transports directly" {
    if (builtin.target.os.tag == .freestanding) return error.SkipZigTest;

    reset();
    defer reset();

    const peripheral_classes = [_]driver_service.DeviceClass{
        .usb_controller,
        .graphics_adapter,
        .audio_print_io,
        .input_device,
        .compositor_policy,
    };
    for (peripheral_classes) |device_class| {
        try std.testing.expect(!(try publishDeviceDataPlane(device_class, @as(u64, 0x9000) + @intFromEnum(device_class), "kernel-device", true)));
        try std.testing.expect(deviceDataPlanePublication(device_class) == null);
    }

    try std.testing.expect(!(try publishDeviceDataPlane(.network_adapter, 0x8086_100E_0001, "generic-network", false)));
    try std.testing.expect(!(try publishDeviceDataPlane(.storage_controller, 0x1F001, "generic-storage", false)));

    try std.testing.expect(try publishDeviceDataPlane(.graphics_adapter, 0x1234_1111_0001, "compositor-driver", false));
    try std.testing.expect(!activateDeviceDataPlane(.graphics_adapter, 0x1234_1111_0002, 44));
    try std.testing.expect(activateDeviceDataPlane(.graphics_adapter, 0x1234_1111_0001, 44));
    try std.testing.expectEqual(@as(u64, 44), deviceDataPlanePublication(.graphics_adapter).?.active_service_id);
    try std.testing.expect(deactivateDeviceDataPlane(.graphics_adapter, 44));
    try std.testing.expectEqual(@as(u64, 0), deviceDataPlanePublication(.graphics_adapter).?.active_service_id);
}
