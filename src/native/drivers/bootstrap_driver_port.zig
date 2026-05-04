const std = @import("std");
const builtin = @import("builtin");
const native_util = @import("../core/util.zig");
const component_port = @import("../kernel_api/component_port.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const device_inventory = @import("device_inventory.zig");
const driver_service = @import("driver_service.zig");
const storage_driver_task = @import("storage_driver_task.zig");
const root = @import("root");
const link_port = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/net/link_port.zig")
else
    struct {
        const StubNetworkDevice = struct {
            send: *const fn ([]const u8) void,
            getMacAddress: *const fn () [6]u8,
        };
        const StubEgressRequest = struct {
            frame: []const u8,
            source_mac: [6]u8,
            egress_capability_id: u64,
            network_policy_id: u64,
        };
        const StubEgressDecision = struct {
            allowed: bool,
            capability_backed: bool,
        };
        const StubEgressBroker = *const fn (request: StubEgressRequest) StubEgressDecision;
        pub const NetworkDevice = StubNetworkDevice;

        var active_device: ?*const StubNetworkDevice = null;
        var egress_broker: ?StubEgressBroker = null;
        var active_egress_capability_id: u64 = 0;
        var active_network_policy_id: u64 = 0;

        pub fn init() void {
            active_device = null;
            egress_broker = null;
            active_egress_capability_id = 0;
            active_network_policy_id = 0;
        }

        pub fn setNetworkDevice(device: *const StubNetworkDevice) void {
            active_device = device;
        }

        pub fn clearNetworkDevice() void {
            active_device = null;
        }

        pub fn hasNetworkDevice() bool {
            return active_device != null;
        }

        pub fn setEgressBroker(broker: ?StubEgressBroker) void {
            egress_broker = broker;
        }

        pub fn bindEgressCapability(capability_id: u64, policy_id: u64) void {
            active_egress_capability_id = capability_id;
            active_network_policy_id = policy_id;
        }

        pub fn clearEgressCapability() void {
            active_egress_capability_id = 0;
            active_network_policy_id = 0;
        }

        pub fn authorizeDriverTx(frame: []const u8) bool {
            const device = active_device orelse return false;
            const broker = egress_broker orelse return false;
            const decision = broker(.{
                .frame = frame,
                .source_mac = device.getMacAddress(),
                .egress_capability_id = active_egress_capability_id,
                .network_policy_id = active_network_policy_id,
            });
            return decision.allowed and decision.capability_backed;
        }

        pub fn sendActiveNetworkFrame(frame: []const u8) bool {
            if (!@This().authorizeDriverTx(frame)) return false;
            const device = active_device orelse return false;
            device.send(frame);
            return true;
        }
    };
const storage_volume = if (builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume"))
    root.storage_volume
else
    @import("../storage/storage_volume.zig");
const copyText = native_util.copyText;

pub const NetworkDevice = link_port.NetworkDevice;
pub const EgressRequest = if (builtin.target.os.tag == .freestanding) link_port.EgressRequest else link_port.StubEgressRequest;
pub const EgressDecision = if (builtin.target.os.tag == .freestanding) link_port.EgressDecision else link_port.StubEgressDecision;
pub const EgressBroker = if (builtin.target.os.tag == .freestanding) link_port.EgressBroker else link_port.StubEgressBroker;
pub const NetworkActivator = *const fn (device_id: u64) ?*const link_port.NetworkDevice;
pub const StorageActivator = *const fn (device_id: u64) ?storage_volume.Backend;

pub const StoragePublicationKind = enum(u8) {
    backend,
    activator,
    ata_bootstrap_bridge,
};

pub const NetworkPublication = struct {
    device_id: u64,
    publisher_len: usize = 0,
    publisher: [32]u8 = [_]u8{0} ** 32,
    network_device: ?*const link_port.NetworkDevice = null,
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

pub fn reset() void {
    published_network = null;
    published_storage = null;
    device_broker.reset();
    link_port.init();
    link_port.clearNetworkDevice();
    storage_volume.clearAttachedBackend();
}

pub fn publishNetworkDevice(
    device_id: u64,
    publisher: []const u8,
    network_device: *const link_port.NetworkDevice,
    kernel_bootstrap: bool,
) bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(NetworkPublication, published_network, device_id)) return false;
    var publication = initPublication(NetworkPublication, device_id, publisher, kernel_bootstrap);
    publication.network_device = network_device;
    published_network = publication;
    return true;
}

pub fn publishNetworkActivator(
    device_id: u64,
    publisher: []const u8,
    activator: NetworkActivator,
    kernel_bootstrap: bool,
) bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(NetworkPublication, published_network, device_id)) return false;
    var publication = initPublication(NetworkPublication, device_id, publisher, kernel_bootstrap);
    publication.activator = activator;
    published_network = publication;
    return true;
}

pub fn publishStorageBackend(
    device_id: u64,
    publisher: []const u8,
    backend: storage_volume.Backend,
    kernel_bootstrap: bool,
) bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(StoragePublication, published_storage, device_id)) return false;
    var publication = initPublication(StoragePublication, device_id, publisher, kernel_bootstrap);
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
) bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(StoragePublication, published_storage, device_id)) return false;
    var publication = initPublication(StoragePublication, device_id, publisher, kernel_bootstrap);
    publication.activator = activator;
    publication.kind = .activator;
    published_storage = publication;
    return true;
}

pub fn publishStorageAtaBootstrap(
    device_id: u64,
    publisher: []const u8,
    kernel_bootstrap: bool,
) bool {
    if (kernel_bootstrap) return false;
    if (!canPublishPublication(StoragePublication, published_storage, device_id)) return false;
    var publication = initPublication(StoragePublication, device_id, publisher, kernel_bootstrap);
    publication.kind = .ata_bootstrap_bridge;
    published_storage = publication;
    return true;
}

pub fn claimStorageAtaBootstrapInventory(driver: *const driver_service.DriverRecord, publisher: []const u8) bool {
    if (driver.device_class != .storage_controller) return false;
    if (driver.bootstrap_transport != .kernel_published_data_plane) return false;

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

pub fn hasActiveNetworkDevice() bool {
    return link_port.hasNetworkDevice();
}

pub fn setEgressBroker(broker: ?EgressBroker) void {
    link_port.setEgressBroker(broker);
}

pub fn bindEgressCapability(capability_id: u64, policy_id: u64) void {
    link_port.bindEgressCapability(capability_id, policy_id);
}

pub fn clearEgressCapability() void {
    link_port.clearEgressCapability();
}

pub fn authorizeDriverTx(frame: []const u8) bool {
    return link_port.authorizeDriverTx(frame);
}

pub fn sendActiveNetworkFrame(frame: []const u8) bool {
    if (builtin.target.os.tag == .freestanding) {
        if (!link_port.authorizeDriverTx(frame)) return false;
        return false;
    }
    return link_port.sendActiveNetworkFrame(frame);
}

pub fn activateNetworkDevice(device_id: u64, service_id: u64) bool {
    if (publicationForActivation(NetworkPublication, &published_network, device_id, service_id)) |publication| {
        if (publication.network_device == null) {
            const activator = publication.activator orelse return false;
            publication.network_device = activator(device_id) orelse return false;
        }
        link_port.init();
        link_port.setNetworkDevice(publication.network_device.?);
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
    now_ticks: u64,
    kernel_port: ?*component_port.KernelPort,
) bool {
    if (publicationForActivation(StoragePublication, &published_storage, device_id, service_id)) |publication| {
        switch (publication.kind) {
            .ata_bootstrap_bridge => {
                const bound_kernel_port = kernel_port orelse return false;
                if (publication.ata_session == null) {
                    publication.ata_session = storage_driver_task.establishAtaBootstrapSession(
                        bound_kernel_port,
                        device_id,
                        authority_capability_id,
                        owner_task_id,
                        now_ticks,
                    ) orelse return false;
                }
                storage_driver_task.attachAtaBootstrapSession(&publication.ata_session.?);
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
        link_port.init();
        link_port.clearNetworkDevice();
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

fn initPublication(comptime T: type, device_id: u64, publisher: []const u8, kernel_bootstrap: bool) T {
    var publication = T{
        .device_id = device_id,
        .kernel_bootstrap = kernel_bootstrap,
    };
    publication.publisher_len = copyText(publication.publisher[0..], publisher);
    return publication;
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
    try std.testing.expect(publishNetworkDevice(7001, "test-net", &device, false));
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
    try std.testing.expect(publishNetworkDevice(7002, "test-net", &device, false));
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

    try std.testing.expect(!publishStorageBackend(0x1F001, "kernel-storage", backend, true));
    try std.testing.expect(!publishStorageActivator(0x1F001, "kernel-storage", Backend.activate, true));
    try std.testing.expect(!publishStorageAtaBootstrap(0x1F001, "kernel-storage", true));
    try std.testing.expect(storagePublication() == null);
}
