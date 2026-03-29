const ethernet = @import("ethernet.zig");

pub const IngressHandler = *const fn (packet: []const u8, mac: [6]u8) void;

pub const NetworkDevice = struct {
    send: *const fn (data: []const u8) void,
    getMacAddress: *const fn () [6]u8,
};

pub const OwnedRxReleaseFn = *const fn (?*anyopaque, handle: usize) void;

pub const OwnedRxPacket = struct {
    data: []const u8,
    mac: [6]u8,
    handle: usize,
    release_context: ?*anyopaque,
    release: OwnedRxReleaseFn,
};

var current_device: ?*const NetworkDevice = null;
var ingress_handler: ?IngressHandler = null;

pub fn init() void {
    ingress_handler = null;
}

pub fn setIngressHandler(handler: ?IngressHandler) void {
    ingress_handler = handler;
}

pub fn setNetworkDevice(device: *const NetworkDevice) void {
    current_device = device;
    ethernet.setTxSender(device.send);
    ethernet.setMacProvider(device.getMacAddress);
}

pub fn clearNetworkDevice() void {
    current_device = null;
    ethernet.setTxSender(null);
    ethernet.setMacProvider(null);
}

pub fn hasNetworkDevice() bool {
    return current_device != null;
}

pub fn enqueueRxPacket(packet: []const u8, mac: [6]u8) void {
    if (ingress_handler) |handler| handler(packet, mac);
}

pub fn enqueueBorrowedRx(packet: OwnedRxPacket) bool {
    defer packet.release(packet.release_context, packet.handle);
    if (ingress_handler) |handler| handler(packet.data, packet.mac);
    return true;
}

pub fn makeRxReleaseAdapter(comptime T: type) OwnedRxReleaseFn {
    return struct {
        fn release(context: ?*anyopaque, handle: usize) void {
            const self: *T = @ptrCast(@alignCast(context orelse return));
            self.releaseReceived(handle);
        }
    }.release;
}
