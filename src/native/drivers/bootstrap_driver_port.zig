const builtin = @import("builtin");
const std = @import("std");
const native_util = @import("../core/util.zig");
const link_port = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/net/link_port.zig")
else
    struct {
        const StubNetworkDevice = struct {
            send: *const fn ([]const u8) void,
            getMacAddress: *const fn () [6]u8,
        };
        pub const NetworkDevice = StubNetworkDevice;

        var active_device: ?*const StubNetworkDevice = null;

        pub fn init() void {
            active_device = null;
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
    };
const storage_volume = @import("../storage/storage_volume.zig");
const storage_volume_backend = @import("../storage/storage_volume_backend.zig");
const copyText = native_util.copyText;

pub const NetworkDevice = link_port.NetworkDevice;
pub const NetworkActivator = *const fn (device_id: u64) ?*const link_port.NetworkDevice;
pub const StorageActivator = *const fn (device_id: u64) ?storage_volume.Backend;

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
    activator: ?StorageActivator = null,
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
    if (!canPublishPublication(StoragePublication, published_storage, device_id)) return false;
    var publication = initPublication(StoragePublication, device_id, publisher, kernel_bootstrap);
    publication.backend = backend;
    published_storage = publication;
    return true;
}

pub fn publishStorageActivator(
    device_id: u64,
    publisher: []const u8,
    activator: StorageActivator,
    kernel_bootstrap: bool,
) bool {
    if (!canPublishPublication(StoragePublication, published_storage, device_id)) return false;
    var publication = initPublication(StoragePublication, device_id, publisher, kernel_bootstrap);
    publication.activator = activator;
    published_storage = publication;
    return true;
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

pub fn activateStorageBackend(device_id: u64, service_id: u64) bool {
    if (publicationForActivation(StoragePublication, &published_storage, device_id, service_id)) |publication| {
        if (publication.backend == null and
            builtin.target.os.tag == .freestanding and
            std.mem.eql(u8, publication.publisherSlice(), "ata-bootstrap"))
        {
            if (!storage_volume_backend.attachDefaultAtaBackendForDevice(device_id)) return false;
        } else {
            if (publication.backend == null) {
                const activator = publication.activator orelse return false;
                publication.backend = activator(device_id) orelse return false;
            }
            storage_volume.attachBackend(publication.backend.?);
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
