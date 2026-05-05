const ethernet = @import("ethernet.zig");

pub const kernel_boundary_role = "bootstrap_network_link_shim";
pub const publishes_full_network_service = false;

pub const IngressHandler = *const fn (packet: []const u8, mac: [6]u8) void;

pub const NetworkDevice = struct {
    send: *const fn (data: []const u8) void,
    getMacAddress: *const fn () [6]u8,
};

pub const EgressRequest = struct {
    frame: []const u8,
    source_mac: [6]u8,
    egress_capability_id: u64,
    network_policy_id: u64,
};

pub const EgressDecision = struct {
    allowed: bool,
    capability_backed: bool,
};

pub const EgressBroker = *const fn (request: EgressRequest) EgressDecision;

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
var egress_broker: ?EgressBroker = null;
var active_egress_capability_id: u64 = 0;
var active_network_policy_id: u64 = 0;

pub fn init() void {
    ingress_handler = null;
    egress_broker = null;
    active_egress_capability_id = 0;
    active_network_policy_id = 0;
}

pub fn setIngressHandler(handler: ?IngressHandler) void {
    ingress_handler = handler;
}

pub fn setEgressBroker(broker: ?EgressBroker) void {
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

pub fn setNetworkDevice(device: *const NetworkDevice) void {
    current_device = device;
    ethernet.setTxSender(brokeredSend);
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

pub fn authorizeDriverTx(frame: []const u8) bool {
    const device = current_device orelse return false;
    const broker = egress_broker orelse return false;
    const decision = broker(.{
        .frame = frame,
        .source_mac = device.getMacAddress(),
        .egress_capability_id = active_egress_capability_id,
        .network_policy_id = active_network_policy_id,
    });
    return decision.allowed and decision.capability_backed;
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

fn brokeredSend(frame: []const u8) void {
    if (!authorizeDriverTx(frame)) return;
    if (current_device) |device| device.send(frame);
}
