const std = @import("std");
const builtin = @import("builtin");
const native_util = @import("../core/util.zig");
const component_port = @import("../kernel_api/component_port.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const device_broker_client = @import("../kernel_api/device_broker_client.zig");
const device_inventory = @import("device_inventory.zig");
const driver_service = @import("driver_service.zig");
const network_driver_task = @import("network_driver_task.zig");
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

const nvme_dma_bridge = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn zigosStorageBootstrapNvmeDmaWindow(
            index: u32,
            base_out: *u64,
            length_out: *u64,
            device_readable_out: *bool,
            device_writable_out: *bool,
        ) callconv(.c) bool;

        pub fn window(index: u32, base_out: *u64, length_out: *u64, device_readable_out: *bool, device_writable_out: *bool) bool {
            return zigosStorageBootstrapNvmeDmaWindow(index, base_out, length_out, device_readable_out, device_writable_out);
        }
    }
else
    struct {
        pub fn window(_: u32, _: *u64, _: *u64, _: *bool, _: *bool) bool {
            return false;
        }
    };

pub const NetworkDevice = network_driver_task.NetworkDevice;
pub const ReceiveStatus = network_driver_task.ReceiveStatus;
pub const ReceiveResult = network_driver_task.ReceiveResult;
pub const ReceiveServiceResult = network_driver_task.ReceiveServiceResult;
pub const noNetworkFrame = network_driver_task.noNetworkFrame;
pub const EgressRequest = network_driver_task.EgressRequest;
pub const EgressDecision = network_driver_task.EgressDecision;
pub const EgressBroker = network_driver_task.EgressBroker;
pub const NetworkActivator = *const fn (device_id: u64) ?*const NetworkDevice;
pub const StorageActivator = *const fn (device_id: u64) ?storage_volume.Backend;
pub const MAX_PUBLISHER_BYTES: usize = 32;
pub const COMPACT_PUBLICATION_METADATA = true;
pub const DEVICE_DATA_PLANE_PUBLICATION_SIZE_CEILING_BYTES: usize = 56;
pub const NETWORK_PUBLICATION_SIZE_CEILING_BYTES: usize = 72;
pub const STORAGE_PUBLICATION_SIZE_CEILING_BYTES: usize = 328;

comptime {
    if (MAX_PUBLISHER_BYTES > std.math.maxInt(u8)) {
        @compileError("driver publication text no longer fits compact metadata");
    }
}

pub const StorageControllerSession = struct {
    kernel_port: *component_port.KernelPort,
    device_id: u64,
    service_id: u64,
    authority_capability_id: u64,
    task_id: u64,
    process_generation: u32,
    dma_domain_id: u64,
    broker_generation: u64,
    dma_isolation: device_broker.DmaIsolationStatus,
    brokered_dma_buffer: device_broker.BrokeredDmaBuffer,
};

pub const DeviceDataPlanePublication = struct {
    device_class: driver_service.DeviceClass = .graphics_adapter,
    device_id: u64,
    publisher_len: u8 = 0,
    publisher: [MAX_PUBLISHER_BYTES]u8 = [_]u8{0} ** MAX_PUBLISHER_BYTES,
    kernel_bootstrap: bool = true,
    active_service_id: u64 = 0,

    pub fn publisherSlice(self: *const DeviceDataPlanePublication) []const u8 {
        return self.publisher[0..@as(usize, self.publisher_len)];
    }

    comptime {
        if (@sizeOf(@This()) > DEVICE_DATA_PLANE_PUBLICATION_SIZE_CEILING_BYTES) {
            @compileError("device data-plane publication exceeds its compact size ceiling");
        }
    }
};

pub const Error = error{
    PublisherTooLong,
};

pub const NetworkPublication = struct {
    device_id: u64,
    publisher_len: u8 = 0,
    publisher: [MAX_PUBLISHER_BYTES]u8 = [_]u8{0} ** MAX_PUBLISHER_BYTES,
    network_device: ?*const NetworkDevice = null,
    activator: ?NetworkActivator = null,
    kernel_bootstrap: bool = true,
    active_service_id: u64 = 0,

    pub fn publisherSlice(self: *const NetworkPublication) []const u8 {
        return self.publisher[0..@as(usize, self.publisher_len)];
    }

    comptime {
        if (@sizeOf(@This()) > NETWORK_PUBLICATION_SIZE_CEILING_BYTES) {
            @compileError("network publication exceeds its compact size ceiling");
        }
    }
};

pub const StoragePublication = struct {
    device_id: u64,
    publisher_len: u8 = 0,
    publisher: [MAX_PUBLISHER_BYTES]u8 = [_]u8{0} ** MAX_PUBLISHER_BYTES,
    backend: ?storage_volume.Backend = null,
    controller_session: ?StorageControllerSession = null,
    activator: ?StorageActivator = null,
    kernel_bootstrap: bool = true,
    active_service_id: u64 = 0,

    pub fn publisherSlice(self: *const StoragePublication) []const u8 {
        return self.publisher[0..@as(usize, self.publisher_len)];
    }

    comptime {
        if (@sizeOf(@This()) > STORAGE_PUBLICATION_SIZE_CEILING_BYTES) {
            @compileError("storage publication exceeds its compact size ceiling");
        }
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

pub fn activePublicationPublisher(
    device_class: driver_service.DeviceClass,
    device_id: u64,
    service_id: u64,
) ?[]const u8 {
    return switch (device_class) {
        .network_adapter => if (published_network) |*publication|
            activePublisherFor(publication, device_id, service_id)
        else
            null,
        .storage_controller => if (published_storage) |*publication|
            activePublisherFor(publication, device_id, service_id)
        else
            null,
        .usb_controller, .graphics_adapter, .audio_print_io, .input_device, .compositor_policy => blk: {
            if (published_device_planes[deviceClassIndex(device_class)]) |*publication| {
                if (publication.device_class != device_class) break :blk null;
                break :blk activePublisherFor(publication, device_id, service_id);
            }
            break :blk null;
        },
    };
}

pub fn publicationUsesKernelBootstrap(
    device_class: driver_service.DeviceClass,
    device_id: u64,
) bool {
    return switch (device_class) {
        .network_adapter => if (published_network) |*publication|
            publication.device_id == device_id and publication.kernel_bootstrap
        else
            false,
        .storage_controller => if (published_storage) |*publication|
            publication.device_id == device_id and publication.kernel_bootstrap
        else
            false,
        .usb_controller, .graphics_adapter, .audio_print_io, .input_device, .compositor_policy => blk: {
            if (published_device_planes[deviceClassIndex(device_class)]) |*publication| {
                break :blk publication.device_class == device_class and
                    publication.device_id == device_id and
                    publication.kernel_bootstrap;
            }
            break :blk false;
        },
    };
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

pub fn authorizeDriverTx(destination: [6]u8, frame: []const u8) bool {
    return network_driver_task.authorizeDriverTx(destination, frame);
}

pub fn sendActiveNetworkFrame(destination: [6]u8, frame: []const u8) bool {
    return network_driver_task.sendActiveFrame(destination, frame);
}

pub fn receiveActiveNetworkFrame(output: []u8) ReceiveResult {
    return network_driver_task.receiveActiveFrame(output);
}

pub fn servicePendingNetworkFrames(budget: usize) ReceiveServiceResult {
    return network_driver_task.servicePendingReceiveFrames(budget);
}

pub fn networkWorkPending() bool {
    return network_driver_task.networkWorkPending();
}

pub fn activeNetworkTaskId() u64 {
    return network_driver_task.activeTaskId();
}

pub fn activateNetworkDevice(device_id: u64, service_id: u64) bool {
    return activateNetworkDeviceForTask(device_id, service_id, 0);
}

pub fn activateNetworkDeviceForTask(device_id: u64, service_id: u64, task_id: u64) bool {
    if (!networkPublicationMatchesTargetI225(device_id)) return false;
    if (publicationForActivation(NetworkPublication, &published_network, device_id, service_id)) |publication| {
        if (publication.network_device == null) {
            const activator = publication.activator orelse return false;
            publication.network_device = activator(device_id) orelse return false;
        }
        if (!kernel_network_claim.recordDriverClaim(device_id, service_id)) return false;
        if (!network_driver_task.activateDeviceForTask(publication.network_device.?, service_id, task_id)) {
            _ = kernel_network_claim.clearDriverClaim(service_id);
            return false;
        }
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
        if (publication.backend == null) {
            const activator = publication.activator orelse return false;
            publication.backend = activator(device_id) orelse return false;
        }
        if (kernel_port) |bound_kernel_port| {
            if (!establishStorageControllerSession(
                publication,
                service_id,
                authority_capability_id,
                owner_task_id,
                dma_domain_id,
                now_ticks,
                bound_kernel_port,
            )) return false;
        } else if (builtin.target.os.tag == .freestanding) {
            return false;
        }
        if (!attachPublishedStorageBackend(publication, publication.backend.?)) return false;
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
        publication.controller_session = null;
        storage_volume.clearAttachedBackend();
        return true;
    }
    return false;
}

pub fn refreshActiveStorageAttachment(service_id: u64) bool {
    const publication = publicationForActiveStorage(service_id) orelse return false;
    const backend = publication.backend orelse return false;
    if (!storageControllerSessionCurrent(publication)) return false;
    return attachPublishedStorageBackend(publication, backend);
}

pub fn activeStorageRead(service_id: u64, start_lba: u64, buffer: []u8) bool {
    const publication = publicationForActiveStorage(service_id) orelse return false;
    const backend = publication.backend orelse return false;
    if (!storageControllerSessionCurrent(publication)) return false;
    return backend.read(start_lba, buffer.ptr, buffer.len);
}

pub fn activeStorageWrite(service_id: u64, start_lba: u64, buffer: []const u8) bool {
    const publication = publicationForActiveStorage(service_id) orelse return false;
    const backend = publication.backend orelse return false;
    if (!storageControllerSessionCurrent(publication)) return false;
    return backend.write(start_lba, buffer.ptr, buffer.len);
}

pub fn activeStorageFlush(service_id: u64) bool {
    const publication = publicationForActiveStorage(service_id) orelse return false;
    const backend = publication.backend orelse return false;
    if (!storageControllerSessionCurrent(publication)) return false;
    return backend.flush();
}

pub fn activeStorageControllerSession(service_id: u64) ?StorageControllerSession {
    const publication = publicationForActiveStorage(service_id) orelse return null;
    if (!storageControllerSessionCurrent(publication)) return null;
    return publication.controller_session;
}

pub fn storageSessionIsCurrent(session: *const StorageControllerSession) bool {
    const task = session.kernel_port.kernel.runtime.find(session.task_id) orelse return false;
    if (task.process_generation != session.process_generation) return false;
    if (device_broker.brokerGeneration(session.device_id) != session.broker_generation) return false;
    return device_broker.brokeredDmaBufferStillValid(session.brokered_dma_buffer);
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

fn activePublisherFor(publication: anytype, device_id: u64, service_id: u64) ?[]const u8 {
    if (service_id == 0 or publication.device_id != device_id or publication.active_service_id != service_id) return null;
    return publication.publisherSlice();
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

fn networkPublicationMatchesTargetI225(device_id: u64) bool {
    const production_device_id = device_inventory.requireProductionDriverDeviceId(.network_adapter) catch return false;
    return production_device_id == device_id;
}

fn publicationForActiveStorage(service_id: u64) ?*StoragePublication {
    if (published_storage) |*publication| {
        if (publication.active_service_id == service_id) return publication;
    }
    return null;
}

fn establishStorageControllerSession(
    publication: *StoragePublication,
    service_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    dma_domain_id: u64,
    now_ticks: u64,
    kernel_port: *component_port.KernelPort,
) bool {
    if (service_id == 0 or authority_capability_id == 0 or owner_task_id == 0 or dma_domain_id == 0) return false;
    const controller_was_published = device_broker.brokerGeneration(publication.device_id) != null;
    if (!controller_was_published and !device_broker.publishPciController(publication.device_id)) return false;
    var client = device_broker_client.Client.init(kernel_port, authority_capability_id, owner_task_id, now_ticks);
    const descriptor = client.describe() catch {
        if (!controller_was_published) _ = device_broker.revokePciController(publication.device_id);
        return false;
    };
    if (descriptor.device_id != publication.device_id) return false;
    if (!programStorageDmaIsolation(publication.device_id, dma_domain_id)) return false;

    const task = kernel_port.kernel.runtime.find(owner_task_id) orelse return false;
    const dma_isolation = device_broker.dmaIsolationStatus(publication.device_id, dma_domain_id) catch return false;
    const staging_window = device_broker.defaultBrokeredDmaWindow(publication.device_id);
    const brokered_dma_buffer = device_broker.authorizeDmaBuffer(
        publication.device_id,
        dma_domain_id,
        staging_window.base,
        staging_window.length,
        .bidirectional,
    ) catch return false;
    publication.controller_session = .{
        .kernel_port = kernel_port,
        .device_id = publication.device_id,
        .service_id = service_id,
        .authority_capability_id = authority_capability_id,
        .task_id = owner_task_id,
        .process_generation = task.process_generation,
        .dma_domain_id = dma_domain_id,
        .broker_generation = device_broker.brokerGeneration(publication.device_id) orelse return false,
        .dma_isolation = dma_isolation,
        .brokered_dma_buffer = brokered_dma_buffer,
    };
    return true;
}

fn storageControllerSessionCurrent(publication: *const StoragePublication) bool {
    const session = publication.controller_session orelse
        return builtin.target.os.tag != .freestanding;
    return storageSessionIsCurrent(&session);
}

fn programStorageDmaIsolation(device_id: u64, dma_domain_id: u64) bool {
    var windows: [device_broker.MAX_DMA_WINDOWS]device_broker.DmaWindow = undefined;
    windows[0] = device_broker.defaultBrokeredDmaWindow(device_id);
    var count: usize = 1;
    while (count < windows.len) : (count += 1) {
        var base: u64 = 0;
        var length: u64 = 0;
        var device_readable = false;
        var device_writable = false;
        if (!nvme_dma_bridge.window(@intCast(count - 1), &base, &length, &device_readable, &device_writable)) break;
        windows[count] = .{
            .base = base,
            .length = length,
            .readable_by_device = device_readable,
            .writable_by_device = device_writable,
            .executable = false,
        };
    }
    if (count == 1) {
        _ = device_broker.programBrokeredDmaIsolation(device_id, dma_domain_id) catch return false;
        return true;
    }
    _ = device_broker.programBusMasterStorageDmaIsolation(device_id, dma_domain_id, windows[0..count]) catch return false;
    return true;
}

fn attachPublishedStorageBackend(publication: *const StoragePublication, backend: storage_volume.Backend) bool {
    if (!storagePublicationMatchesTargetNvme(publication)) return false;
    storage_volume.attachNvmePciBackend(backend);
    return storage_volume.hasProductionStorageBackend();
}

fn storagePublicationMatchesTargetNvme(publication: *const StoragePublication) bool {
    const inventory = device_inventory.recordForClass(.storage_controller);
    return inventory.detected and
        inventory.device_id == publication.device_id and
        device_inventory.sourceCanBindProductionDriver(.storage_controller, inventory.source, inventory.device_id);
}

fn initPublication(comptime T: type, device_id: u64, publisher: []const u8, kernel_bootstrap: bool) Error!T {
    var publication = T{
        .device_id = device_id,
        .kernel_bootstrap = kernel_bootstrap,
    };
    publication.publisher_len = @intCast(native_util.copyTextExact(publication.publisher[0..], publisher) catch return error.PublisherTooLong);
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

test "bootstrap driver publications use compact bounded metadata" {
    try std.testing.expect(COMPACT_PUBLICATION_METADATA);
    try std.testing.expectEqual(u8, @FieldType(DeviceDataPlanePublication, "publisher_len"));
    try std.testing.expectEqual(u8, @FieldType(NetworkPublication, "publisher_len"));
    try std.testing.expectEqual(u8, @FieldType(StoragePublication, "publisher_len"));
    try std.testing.expectEqual(
        @as(usize, DEVICE_DATA_PLANE_PUBLICATION_SIZE_CEILING_BYTES),
        @sizeOf(DeviceDataPlanePublication),
    );
    try std.testing.expectEqual(@as(usize, NETWORK_PUBLICATION_SIZE_CEILING_BYTES), @sizeOf(NetworkPublication));
    try std.testing.expectEqual(@as(usize, STORAGE_PUBLICATION_SIZE_CEILING_BYTES), @sizeOf(StoragePublication));
}

test "driver-backed network tx fails closed without capability-backed egress decision" {
    if (builtin.target.os.tag == .freestanding) return error.SkipZigTest;

    reset();
    defer reset();
    device_inventory.reset();
    defer device_inventory.reset();
    const i225_device_id: u64 = 0x8086_15F2_0001;

    const Harness = struct {
        var send_count: usize = 0;
        var saw_policy_id: u64 = 0;
        var saw_capability_id: u64 = 0;

        fn send(_: [6]u8, _: []const u8) bool {
            send_count += 1;
            return true;
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
        .receive = noNetworkFrame,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(try publishNetworkDevice(i225_device_id, "i225-userspace", &device, false));
    try std.testing.expect(!activateNetworkDevice(i225_device_id, 9));
    device_inventory.registerDetected(.network_adapter, i225_device_id, .intel_i225_lm_inventory, false);
    try std.testing.expect(activateNetworkDevice(i225_device_id, 9));

    const frame_with_raw_destination = "GET / HTTP/1.1\r\nHost: relay.zigos.dev\r\nX-IP: 203.0.113.7\r\n\r\n";
    const peer_mac = [_]u8{ 0x02, 0, 0, 0, 0, 0x44 };
    try std.testing.expect(!sendActiveNetworkFrame(peer_mac, frame_with_raw_destination));
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    setEgressBroker(Harness.broker);
    try std.testing.expect(!sendActiveNetworkFrame(peer_mac, frame_with_raw_destination));
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);
    try std.testing.expectEqual(@as(u64, 0), Harness.saw_capability_id);

    bindEgressCapability(99, 44);
    try std.testing.expect(sendActiveNetworkFrame(peer_mac, frame_with_raw_destination));
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
    try std.testing.expectEqual(@as(u64, 44), Harness.saw_policy_id);
    try std.testing.expectEqual(@as(u64, 99), Harness.saw_capability_id);
}

test "adversarial raw IP or domain knowledge cannot substitute for egress capability" {
    if (builtin.target.os.tag == .freestanding) return error.SkipZigTest;

    reset();
    defer reset();
    device_inventory.reset();
    defer device_inventory.reset();
    const i225_device_id: u64 = 0x8086_15F2_0001;

    const Harness = struct {
        var send_count: usize = 0;

        fn send(_: [6]u8, _: []const u8) bool {
            send_count += 1;
            return true;
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
        .receive = noNetworkFrame,
        .getMacAddress = Harness.mac,
    };
    device_inventory.registerDetected(.network_adapter, i225_device_id, .intel_i225_lm_inventory, false);
    try std.testing.expect(try publishNetworkDevice(i225_device_id, "i225-userspace", &device, false));
    try std.testing.expect(activateNetworkDevice(i225_device_id, 10));
    setEgressBroker(Harness.adversarialBroker);

    const forged_frame = "dst=203.0.113.7; host=relay.zigos.dev";
    const peer_mac = [_]u8{ 0x02, 0, 0, 0, 0, 0x45 };
    try std.testing.expect(!sendActiveNetworkFrame(peer_mac, forged_frame));
    try std.testing.expectEqual(@as(usize, 0), Harness.send_count);

    bindEgressCapability(31337, 5150);
    try std.testing.expect(sendActiveNetworkFrame(peer_mac, forged_frame));
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

        fn flush() callconv(.c) bool {
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
        .flush = Backend.flush,
    };

    try std.testing.expect(!(try publishStorageBackend(0x1F001, "kernel-storage", backend, true)));
    try std.testing.expect(!(try publishStorageActivator(0x1F001, "kernel-storage", Backend.activate, true)));
    try std.testing.expect(storagePublication() == null);
}

test "active storage attachment refreshes from the publication" {
    if (builtin.target.os.tag == .freestanding) return error.SkipZigTest;

    reset();
    defer reset();
    device_inventory.reset();
    defer device_inventory.reset();

    const Backend = struct {
        fn read(_: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
            @memset(buffer_ptr[0..buffer_len], 0);
            return true;
        }

        fn write(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return true;
        }

        fn flush() callconv(.c) bool {
            return true;
        }
    };
    const backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors,
        .read = Backend.read,
        .write = Backend.write,
        .flush = Backend.flush,
    };
    const device_id: u64 = 0x0000_8086_5845_5101;
    const service_id: u64 = 0x5102;
    device_inventory.registerDetected(.storage_controller, device_id, .nvme_pci_inventory, false);

    try std.testing.expect(try publishStorageBackend(device_id, "test-storage", backend, false));
    try std.testing.expect(activateStorageBackend(device_id, service_id, 0, 0, 1, 0, null));
    try std.testing.expect(storage_volume.hasAttachedDevice());
    try std.testing.expect(storage_volume.hasProductionStorageBackend());

    storage_volume.clearAttachedBackend();
    try std.testing.expect(!storage_volume.hasAttachedDevice());
    try std.testing.expect(refreshActiveStorageAttachment(service_id));
    try std.testing.expect(storage_volume.hasAttachedDevice());
    try std.testing.expect(storage_volume.hasProductionStorageBackend());
}

test "storage backend activation requires target nvme inventory" {
    if (builtin.target.os.tag == .freestanding) return error.SkipZigTest;

    reset();
    defer reset();
    device_inventory.reset();
    defer device_inventory.reset();

    const Backend = struct {
        fn read(_: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
            @memset(buffer_ptr[0..buffer_len], 0);
            return true;
        }

        fn write(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return true;
        }

        fn flush() callconv(.c) bool {
            return true;
        }
    };
    const backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors,
        .read = Backend.read,
        .write = Backend.write,
        .flush = Backend.flush,
    };

    const uninventoried_device_id: u64 = 0x0000_8086_5845_5201;
    try std.testing.expect(try publishStorageBackend(uninventoried_device_id, "test-storage", backend, false));
    try std.testing.expect(!activateStorageBackend(uninventoried_device_id, 0x5202, 0, 0, 1, 0, null));
    try std.testing.expect(!storage_volume.hasAttachedDevice());

    reset();
    const non_nvme_device_id: u64 = 0x0000_8086_5845_5203;
    device_inventory.registerDetected(.storage_controller, non_nvme_device_id, .pci_inventory, false);
    try std.testing.expect(try publishStorageBackend(non_nvme_device_id, "test-storage", backend, false));
    try std.testing.expect(!activateStorageBackend(non_nvme_device_id, 0x5204, 0, 0, 1, 0, null));
    try std.testing.expect(!storage_volume.hasAttachedDevice());
}

test "active nvme controller sessions reject stale broker generations" {
    if (builtin.target.os.tag == .freestanding) return error.SkipZigTest;

    const capability = @import("../kernel_api/capability.zig");
    const endpoint = @import("../kernel_api/endpoint.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const principal = @import("../core/principal.zig");
    const shared_memory = @import("../kernel_api/shared_memory.zig");
    const generated_image_fixtures = @import("../task/generated_image_fixtures.zig");
    const task_runtime = @import("../task/task_runtime.zig");
    const units = @import("../core/units.zig");

    reset();
    defer reset();
    device_inventory.reset();
    defer device_inventory.reset();
    storage_volume.clearAttachedBackend();
    defer storage_volume.clearAttachedBackend();

    const device_id: u64 = 0x0000_8086_5845_5103;
    const service_id: u64 = 0x5104;
    const dma_domain_id: u64 = 0xD512;

    const Backing = struct {
        var bytes = [_]u8{0} ** (storage_volume.sector_size * 8);

        fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
            const offset = std.math.mul(usize, @intCast(start_lba), storage_volume.sector_size) catch return false;
            if (offset > bytes.len or buffer_len > bytes.len - offset) return false;
            @memcpy(buffer_ptr[0..buffer_len], bytes[offset .. offset + buffer_len]);
            return true;
        }

        fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
            const offset = std.math.mul(usize, @intCast(start_lba), storage_volume.sector_size) catch return false;
            if (offset > bytes.len or buffer_len > bytes.len - offset) return false;
            @memcpy(bytes[offset .. offset + buffer_len], buffer_ptr[0..buffer_len]);
            return true;
        }

        fn flush() callconv(.c) bool {
            return true;
        }
    };
    @memset(Backing.bytes[0..], 0);
    device_inventory.registerDetected(.storage_controller, device_id, .nvme_pci_inventory, false);
    const backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors,
        .read = Backing.read,
        .write = Backing.write,
        .flush = Backing.flush,
    };

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

    const owner = principal.PrincipalId{ .kind = .service, .serial = service_id };
    const storage_driver_image = try generated_image_fixtures.storageDriverImage();
    const driver_task = try runtime.createTask(.{
        .owner = owner,
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
            .image_id = 51,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.storage-driver",
        },
        .userspace_image = &storage_driver_image,
    });
    const authority = try driver_service.mintDriverAuthority(&capabilities, .{
        .holder = owner,
        .task_id = driver_task.id,
        .device_id = device_id,
        .device_class = .storage_controller,
    });
    try runtime.grantCapability(driver_task.id, authority.id);

    try std.testing.expect(try publishStorageBackend(device_id, "zigos.system.storage-driver", backend, false));
    try std.testing.expect(activateStorageBackend(
        device_id,
        service_id,
        authority.id,
        driver_task.id,
        dma_domain_id,
        7,
        &kernel_port,
    ));

    var before_revoke = [_]u8{0x61} ** storage_volume.sector_size;
    const label = "before-broker-revoke";
    @memcpy(before_revoke[0..label.len], label);
    try std.testing.expect(activeStorageWrite(service_id, 6, before_revoke[0..]));

    const stale_session = activeStorageControllerSession(service_id).?;
    const previous_generation = stale_session.broker_generation;
    try std.testing.expect(device_broker.revokePciController(device_id));
    try std.testing.expect(!device_broker.brokeredDmaBufferStillValid(stale_session.brokered_dma_buffer));

    var readback = [_]u8{0} ** storage_volume.sector_size;
    try std.testing.expect(!activeStorageRead(service_id, 6, readback[0..]));
    try std.testing.expect(device_broker.publishPciController(device_id));
    try std.testing.expect(!storageSessionIsCurrent(&stale_session));
    try std.testing.expect(deactivateStorageBackend(service_id));
    try std.testing.expect(activateStorageBackend(
        device_id,
        service_id,
        authority.id,
        driver_task.id,
        dma_domain_id,
        8,
        &kernel_port,
    ));
    try std.testing.expect(activeStorageRead(service_id, 6, readback[0..]));
    try std.testing.expect(std.mem.eql(u8, before_revoke[0..], readback[0..]));
    try std.testing.expect(storage_volume.hasAttachedDevice());

    const repaired_session = activeStorageControllerSession(service_id).?;
    try std.testing.expect(repaired_session.broker_generation != previous_generation);
    try std.testing.expect(device_broker.brokeredDmaBufferStillValid(repaired_session.brokered_dma_buffer));

    const repaired_process_generation = repaired_session.process_generation;
    try std.testing.expect(try runtime.rehostTask(driver_task.id, 9));
    try std.testing.expect(!refreshActiveStorageAttachment(service_id));
    try std.testing.expect(deactivateStorageBackend(service_id));
    try std.testing.expect(activateStorageBackend(
        device_id,
        service_id,
        authority.id,
        driver_task.id,
        dma_domain_id,
        10,
        &kernel_port,
    ));

    const rehosted_session = activeStorageControllerSession(service_id).?;
    try std.testing.expect(rehosted_session.process_generation != repaired_process_generation);
    try std.testing.expect(device_broker.brokeredDmaBufferStillValid(rehosted_session.brokered_dma_buffer));

    @memset(readback[0..], 0);
    try std.testing.expect(activeStorageRead(service_id, 6, readback[0..]));
    try std.testing.expect(std.mem.eql(u8, before_revoke[0..], readback[0..]));
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

    try std.testing.expect(!(try publishDeviceDataPlane(.network_adapter, 0x8086_15F2_0001, "generic-network", false)));
    try std.testing.expect(!(try publishDeviceDataPlane(.storage_controller, 0x1F001, "generic-storage", false)));

    try std.testing.expect(try publishDeviceDataPlane(.graphics_adapter, 0x1234_1111_0001, "compositor-driver", false));
    try std.testing.expect(!activateDeviceDataPlane(.graphics_adapter, 0x1234_1111_0002, 44));
    try std.testing.expect(activateDeviceDataPlane(.graphics_adapter, 0x1234_1111_0001, 44));
    try std.testing.expectEqual(@as(u64, 44), deviceDataPlanePublication(.graphics_adapter).?.active_service_id);
    try std.testing.expect(deactivateDeviceDataPlane(.graphics_adapter, 44));
    try std.testing.expectEqual(@as(u64, 0), deviceDataPlanePublication(.graphics_adapter).?.active_service_id);
}
