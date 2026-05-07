const std = @import("std");

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

var active_device: ?*const NetworkDevice = null;
var active_service_id: u64 = 0;
var egress_broker: ?EgressBroker = null;
var active_egress_capability_id: u64 = 0;
var active_network_policy_id: u64 = 0;

pub fn reset() void {
    active_device = null;
    active_service_id = 0;
    egress_broker = null;
    active_egress_capability_id = 0;
    active_network_policy_id = 0;
}

pub fn activateDevice(device: *const NetworkDevice, service_id: u64) bool {
    if (service_id == 0) return false;
    active_device = device;
    active_service_id = service_id;
    return true;
}

pub fn deactivateDevice(service_id: u64) bool {
    if (active_service_id != service_id) return false;
    active_device = null;
    active_service_id = 0;
    clearEgressCapability();
    return true;
}

pub fn hasActiveDevice() bool {
    return active_device != null;
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

pub fn sendActiveFrame(frame: []const u8) bool {
    if (!authorizeDriverTx(frame)) return false;
    const device = active_device orelse return false;
    device.send(frame);
    return true;
}

test "network driver data plane is brokered by explicit egress capability" {
    const Harness = struct {
        var send_count: usize = 0;

        fn send(_: []const u8) void {
            send_count += 1;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 1 };
        }

        fn broker(request: EgressRequest) EgressDecision {
            return .{
                .allowed = request.network_policy_id == 41,
                .capability_backed = request.egress_capability_id == 99,
            };
        }
    };

    reset();
    defer reset();

    const device = NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(activateDevice(&device, 7));
    try std.testing.expect(!sendActiveFrame("frame"));
    setEgressBroker(Harness.broker);
    try std.testing.expect(!sendActiveFrame("frame"));
    bindEgressCapability(99, 41);
    try std.testing.expect(sendActiveFrame("frame"));
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
}
