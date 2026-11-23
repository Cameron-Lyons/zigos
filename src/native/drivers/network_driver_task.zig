const std = @import("std");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const table_backing = @import("../core/table_backing.zig");
pub const ReceiveStatus = enum(u8) {
    empty = 0,
    frame = 1,
    dropped = 2,
    failed = 3,
};

pub const ReceiveResult = struct {
    status: ReceiveStatus,
    length: u16 = 0,
};

pub fn noNetworkFrame(_: []u8) ReceiveResult {
    return .{ .status = .empty };
}

pub fn noNetworkWorkPending() bool {
    return false;
}

pub fn noNetworkWake() ?u64 {
    return null;
}

pub const NetworkDevice = struct {
    send: *const fn (destination: [6]u8, data: []const u8) bool,
    receive: *const fn (output: []u8) ReceiveResult,
    workPending: *const fn () bool = noNetworkWorkPending,
    nextWake: *const fn () ?u64 = noNetworkWake,
    getMacAddress: *const fn () [6]u8,
};

pub const BROADCAST_MAC: [6]u8 = @as([6]u8, @splat(0xFF));
pub const MAX_PEER_LINKS: usize = 32;
pub const USERSPACE_I225_DATAPLANE = true;
pub const KERNEL_LATCHES_ONLY = true;
const PEER_LINK_INDEX_CAPACITY: usize = MAX_PEER_LINKS * 2;
const PeerLinkIndex = indexed_arena.UniqueIndex(PEER_LINK_INDEX_CAPACITY);

const PeerLink = struct {
    device: principal.PrincipalId = .{ .kind = .device, .serial = 0 },
    mac: [6]u8 = @as([6]u8, @splat(0)),
};

pub const PeerLinkError = error{
    InvalidPeerDevice,
    InvalidPeerAddress,
    PeerAddressConflict,
    PeerLinkDirectoryFull,
    NoSpaceLeft,
};

const PeerLinkDirectoryState = struct {
    links: [MAX_PEER_LINKS]PeerLink = @as([MAX_PEER_LINKS]PeerLink, @splat(.{})),
    link_count: usize = 0,
    device_index: PeerLinkIndex = PeerLinkIndex.init(),
    mac_index: PeerLinkIndex = PeerLinkIndex.init(),

    fn bindValidated(self: *PeerLinkDirectoryState, device: principal.PrincipalId, mac: [6]u8) PeerLinkError!void {
        if (self.device_index.lookup(device.serial)) |index| {
            if (index >= self.link_count) native_util.impossibleByInvariant("peer device index points outside live links");
            const link = &self.links[index];
            if (!link.device.eql(device)) native_util.impossibleByInvariant("peer device index points at the wrong link");
            if (!std.mem.eql(u8, &link.mac, &mac)) return error.PeerAddressConflict;
            return;
        }
        if (self.mac_index.contains(macIndexKey(mac))) return error.PeerAddressConflict;
        if (self.link_count == MAX_PEER_LINKS) return error.PeerLinkDirectoryFull;

        const index = self.link_count;
        self.links[index] = .{ .device = device, .mac = mac };
        self.device_index.insert(device.serial, index);
        self.mac_index.insert(macIndexKey(mac), index);
        self.link_count += 1;
    }

    pub fn resolve(self: *const PeerLinkDirectoryState, device: principal.PrincipalId) ?[6]u8 {
        if (device.kind != .device or device.serial == 0) return null;
        const index = self.device_index.lookup(device.serial) orelse return null;
        if (index >= self.link_count) native_util.impossibleByInvariant("peer device index points outside live links");
        const link = &self.links[index];
        if (!link.device.eql(device)) native_util.impossibleByInvariant("peer device index points at the wrong link");
        return link.mac;
    }
};

pub const PeerLinkDirectory = struct {
    backing: table_backing.Lazy(PeerLinkDirectoryState, null) = .{},

    fn stateConst(self: *const PeerLinkDirectory) ?*const PeerLinkDirectoryState {
        return self.backing.get();
    }

    pub fn bind(self: *PeerLinkDirectory, device: principal.PrincipalId, mac: [6]u8) PeerLinkError!void {
        if (device.kind != .device or device.serial == 0) return error.InvalidPeerDevice;
        if (!validUnicastMac(mac)) return error.InvalidPeerAddress;
        try (try self.backing.ensure()).bindValidated(device, mac);
    }

    pub fn resolve(self: *const PeerLinkDirectory, device: principal.PrincipalId) ?[6]u8 {
        const directory = self.stateConst() orelse return null;
        return directory.resolve(device);
    }

    pub fn count(self: *const PeerLinkDirectory) usize {
        const directory = self.stateConst() orelse return 0;
        return directory.link_count;
    }

    pub fn reset(self: *PeerLinkDirectory) void {
        self.backing.release();
    }

    pub fn deinit(self: *PeerLinkDirectory) void {
        self.reset();
    }
};

fn macIndexKey(mac: [6]u8) u64 {
    var key: u64 = 0;
    for (mac) |byte| key = (key << 8) | byte;
    return key;
}

pub fn validUnicastMac(mac: [6]u8) bool {
    if ((mac[0] & 1) != 0) return false;
    var any_nonzero = false;
    var any_not_ff = false;
    for (mac) |byte| {
        any_nonzero = any_nonzero or byte != 0;
        any_not_ff = any_not_ff or byte != 0xFF;
    }
    return any_nonzero and any_not_ff;
}

pub const EgressRequest = struct {
    frame: []const u8,
    source_mac: [6]u8,
    destination_mac: [6]u8,
    egress_capability_id: u64,
    network_policy_id: u64,
};

pub const EgressDecision = struct {
    allowed: bool,
    capability_backed: bool,
};

pub const EgressBroker = *const fn (request: EgressRequest) EgressDecision;
pub const MAX_NATIVE_FRAME_BYTES: usize = 256;
pub const MAX_RECEIVE_FRAME_BYTES: usize = 1500;
pub const RECEIVE_QUEUE_CAPACITY: usize = 32;
pub const RECEIVE_RESULT_SIZE_CEILING_BYTES: usize = 4;
pub const QUEUED_RECEIVE_FRAME_SIZE_CEILING_BYTES: usize = 1_502;
pub const RECEIVE_PREFIX_BYTES: usize = 4;

comptime {
    if (RECEIVE_QUEUE_CAPACITY > std.math.maxInt(u8)) {
        @compileError("network driver queue metadata exceeds u8 capacity");
    }
    if (MAX_NATIVE_FRAME_BYTES > std.math.maxInt(u16) or MAX_RECEIVE_FRAME_BYTES > std.math.maxInt(u16)) {
        @compileError("network driver frame metadata exceeds u16 capacity");
    }
    if (@sizeOf(ReceiveResult) > RECEIVE_RESULT_SIZE_CEILING_BYTES) {
        @compileError("network driver receive result exceeds its compact layout ceiling");
    }
}

var active_device: ?*const NetworkDevice = null;
var active_service_id: u64 = 0;
var active_task_id: u64 = 0;
var egress_broker: ?EgressBroker = null;
var active_egress_capability_id: u64 = 0;
var active_network_policy_id: u64 = 0;
var active_driver_tx_count: usize = 0;

const QueuedReceiveFrame = struct {
    length: u16 = 0,
    bytes: [MAX_RECEIVE_FRAME_BYTES]u8 = @as([MAX_RECEIVE_FRAME_BYTES]u8, @splat(0)),
};
const ReceiveQueue = [RECEIVE_QUEUE_CAPACITY]QueuedReceiveFrame;
comptime {
    if (@sizeOf(QueuedReceiveFrame) > QUEUED_RECEIVE_FRAME_SIZE_CEILING_BYTES) {
        @compileError("network driver receive queue frame exceeds its compact layout ceiling");
    }
}

// Received frames are queued only for the registered consumer prefix. Every
// other frame drains from hardware into a zero-length buffer, so nothing is
// copied, queued or woken for traffic no reader consumes. The prefix and its
// queue persist until reset: consumer frames that arrive while it has no
// session stay queued (tail-dropped when full) until it drains them.
var receive_prefix: ?[RECEIVE_PREFIX_BYTES]u8 = null;
var receive_queue: table_backing.Lazy(ReceiveQueue, null) = .{};
var receive_queue_head: u8 = 0;
var receive_queue_count: u8 = 0;

pub const ReceiveServiceResult = struct {
    polls: usize = 0,
    frames_queued: usize = 0,
    dropped: usize = 0,
    failed: bool = false,
};

pub fn reset() void {
    active_device = null;
    active_service_id = 0;
    active_task_id = 0;
    egress_broker = null;
    active_egress_capability_id = 0;
    active_network_policy_id = 0;
    active_driver_tx_count = 0;
    receive_prefix = null;
    releaseReceiveQueue();
}

pub fn activateDevice(device: *const NetworkDevice, service_id: u64) bool {
    return activateDeviceForTask(device, service_id, 0);
}

pub fn activateDeviceForTask(device: *const NetworkDevice, service_id: u64, task_id: u64) bool {
    if (service_id == 0) return false;
    clearReceiveQueue();
    active_device = device;
    active_service_id = service_id;
    active_task_id = task_id;
    return true;
}

pub fn deactivateDevice(service_id: u64) bool {
    if (active_service_id != service_id) return false;
    active_device = null;
    active_service_id = 0;
    active_task_id = 0;
    clearReceiveQueue();
    clearEgressCapability();
    return true;
}

/// Registers the consumer whose frames the receive path queues. Returns
/// false when the queue cannot be allocated.
pub fn acceptReceivePrefix(prefix: [RECEIVE_PREFIX_BYTES]u8) bool {
    if (receive_prefix) |current| {
        if (std.mem.eql(u8, &current, &prefix)) return true;
    }
    if (ensureReceiveQueue() == null) return false;
    clearReceiveQueue();
    receive_prefix = prefix;
    return true;
}

pub fn hasActiveDevice() bool {
    return active_device != null;
}

pub fn activeMacAddress() ?[6]u8 {
    const device = active_device orelse return null;
    return device.getMacAddress();
}

pub fn activeTaskId() u64 {
    return active_task_id;
}

pub fn networkWorkPending() bool {
    const device = active_device orelse return false;
    return device.workPending();
}

pub fn nextNetworkWake() ?u64 {
    const device = active_device orelse return null;
    return device.nextWake();
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

fn receiveQueue() ?*ReceiveQueue {
    return receive_queue.get();
}

fn ensureReceiveQueue() ?*ReceiveQueue {
    return receive_queue.ensure() catch null;
}

fn clearReceiveQueue() void {
    receive_queue_head = 0;
    receive_queue_count = 0;
}

fn releaseReceiveQueue() void {
    clearReceiveQueue();
    receive_queue.release();
}

pub fn activeDriverTransmitCount() usize {
    return active_driver_tx_count;
}

fn authorizeDriverTx(destination: [6]u8, frame: []const u8) bool {
    if (!validUnicastMac(destination) and !std.mem.eql(u8, &destination, &BROADCAST_MAC)) return false;
    const device = active_device orelse return false;
    const broker = egress_broker orelse return false;
    const decision = broker(.{
        .frame = frame,
        .source_mac = device.getMacAddress(),
        .destination_mac = destination,
        .egress_capability_id = active_egress_capability_id,
        .network_policy_id = active_network_policy_id,
    });
    return decision.allowed and decision.capability_backed;
}

pub fn sendActiveFrame(destination: [6]u8, frame: []const u8) bool {
    if (frame.len > MAX_NATIVE_FRAME_BYTES) return false;
    if (!authorizeDriverTx(destination, frame)) return false;
    const device = active_device orelse return false;
    if (!device.send(destination, frame)) return false;
    active_driver_tx_count += 1;
    return true;
}

/// Dequeues the oldest frame of the registered consumer without polling
/// hardware. A frame longer than `output` is consumed and reported dropped.
pub fn receiveQueuedFrame(output: []u8) ReceiveResult {
    if (receive_queue_count == 0) return .{ .status = .empty };
    const queue = receiveQueue() orelse return .{ .status = .empty };
    const frame = &queue[receive_queue_head];
    receive_queue_head = @intCast((@as(usize, receive_queue_head) + 1) % RECEIVE_QUEUE_CAPACITY);
    receive_queue_count -= 1;
    if (frame.length > output.len) return .{ .status = .dropped };
    @memcpy(output[0..frame.length], frame.bytes[0..frame.length]);
    return .{ .status = .frame, .length = frame.length };
}

pub fn hasQueuedFrame() bool {
    return receive_queue_count != 0;
}

pub fn servicePendingReceiveFrames(budget: usize) ReceiveServiceResult {
    const device = active_device orelse return .{};
    if (budget == 0 or !device.workPending()) return .{};
    const prefix = receive_prefix orelse return drainReceiveFrames(device, budget);
    const queue = receiveQueue() orelse return .{ .failed = true };
    return queueReceiveFrames(device, queue, &prefix, budget);
}

fn drainReceiveFrames(device: *const NetworkDevice, budget: usize) ReceiveServiceResult {
    var service = ReceiveServiceResult{};
    var empty_output: [0]u8 = .{};
    while (service.polls < budget) {
        const result = device.receive(&empty_output);
        service.polls += 1;
        if (!countReceiveResult(&service, result, 0)) return service;
        if (result.status == .frame) service.dropped += 1;
    }
    return service;
}

fn queueReceiveFrames(device: *const NetworkDevice, queue: *ReceiveQueue, prefix: []const u8, budget: usize) ReceiveServiceResult {
    var service = ReceiveServiceResult{};
    var empty_output: [0]u8 = .{};
    while (service.polls < budget) {
        const tail_index = (@as(usize, receive_queue_head) + receive_queue_count) % RECEIVE_QUEUE_CAPACITY;
        const tail: ?*QueuedReceiveFrame = if (receive_queue_count < RECEIVE_QUEUE_CAPACITY) &queue[tail_index] else null;
        const output: []u8 = if (tail) |frame| &frame.bytes else &empty_output;
        const result = device.receive(output);
        service.polls += 1;
        if (!countReceiveResult(&service, result, output.len)) return service;
        if (result.status != .frame) continue;
        const frame = tail orelse {
            service.dropped += 1;
            continue;
        };
        if (!std.mem.startsWith(u8, frame.bytes[0..result.length], prefix)) {
            service.dropped += 1;
            continue;
        }
        frame.length = result.length;
        receive_queue_count += 1;
        service.frames_queued += 1;
    }
    return service;
}

// Returns false when polling must stop: the device is empty or violated its
// receive contract.
fn countReceiveResult(service: *ReceiveServiceResult, result: ReceiveResult, output_len: usize) bool {
    switch (result.status) {
        .empty => {
            if (result.length != 0) service.failed = true;
            return false;
        },
        .dropped => {
            if (result.length != 0) {
                service.failed = true;
                return false;
            }
            service.dropped += 1;
            return true;
        },
        .failed => {
            service.failed = true;
            return false;
        },
        .frame => {
            if (output_len == 0) return true;
            if (result.length == 0 or result.length > output_len) {
                service.failed = true;
                return false;
            }
            return true;
        },
    }
}

const ReceiveHarness = struct {
    var frames: []const []const u8 = &.{};
    var next: usize = 0;
    var empty_output_drains: usize = 0;

    fn start(sequence: []const []const u8) void {
        frames = sequence;
        next = 0;
        empty_output_drains = 0;
    }

    fn send(_: [6]u8, _: []const u8) bool {
        return true;
    }

    fn mac() [6]u8 {
        return .{ 0x02, 0, 0, 0, 0, 3 };
    }

    fn pending() bool {
        return next < frames.len;
    }

    fn receive(output: []u8) ReceiveResult {
        if (!pending()) return .{ .status = .empty };
        const bytes = frames[next];
        next += 1;
        if (output.len == 0) empty_output_drains += 1;
        if (output.len < bytes.len) return .{ .status = .dropped };
        @memcpy(output[0..bytes.len], bytes);
        return .{ .status = .frame, .length = @intCast(bytes.len) };
    }

    const device = NetworkDevice{
        .send = send,
        .receive = receive,
        .workPending = pending,
        .getMacAddress = mac,
    };
};

test "peer link directory binds stable unicast routes and rejects ambiguity" {
    var directory = PeerLinkDirectory{};
    defer directory.deinit();
    const first_device = principal.PrincipalId{ .kind = .device, .serial = 1 };
    const second_device = principal.PrincipalId{ .kind = .device, .serial = 2 };
    const first_mac = [_]u8{ 0x02, 0x5A, 0x47, 0, 0, 1 };
    const second_mac = [_]u8{ 0x02, 0x5A, 0x47, 0, 0, 2 };

    try directory.bind(first_device, first_mac);
    try directory.bind(first_device, first_mac);
    try std.testing.expectEqual(@as(usize, 1), directory.count());
    const resolved = directory.resolve(first_device).?;
    try std.testing.expectEqualSlices(u8, &first_mac, &resolved);
    try std.testing.expect(directory.resolve(second_device) == null);
    try std.testing.expect(directory.resolve(.{ .kind = .service, .serial = first_device.serial }) == null);

    try std.testing.expectError(error.InvalidPeerDevice, directory.bind(.{ .kind = .service, .serial = 3 }, second_mac));
    try std.testing.expectError(error.InvalidPeerAddress, directory.bind(second_device, @as([6]u8, @splat(0))));
    try std.testing.expectError(error.InvalidPeerAddress, directory.bind(second_device, .{ 0x01, 0, 0, 0, 0, 2 }));
    try std.testing.expectError(error.PeerAddressConflict, directory.bind(first_device, second_mac));
    try std.testing.expectError(error.PeerAddressConflict, directory.bind(second_device, first_mac));
    try std.testing.expectEqual(@as(usize, 1), directory.count());
}

test "network driver keeps bounded frame metadata compact" {
    try std.testing.expectEqual(u16, @FieldType(ReceiveResult, "length"));
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(ReceiveResult));
    try std.testing.expectEqual(@as(usize, 1_502), @sizeOf(QueuedReceiveFrame));
    try std.testing.expectEqual(@as(usize, 48_064), @sizeOf(ReceiveQueue));
    try std.testing.expectEqual(@sizeOf(?*anyopaque), @sizeOf(?*ReceiveQueue));
    try std.testing.expectEqual(u8, @TypeOf(receive_queue_head));
    try std.testing.expectEqual(u8, @TypeOf(receive_queue_count));
    try std.testing.expectEqual(@as(usize, 1_928), @sizeOf(PeerLinkDirectoryState));
    try std.testing.expectEqual(@sizeOf(?*anyopaque), @sizeOf(?*PeerLinkDirectoryState));
}

test "peer link directory has a fixed fail-closed capacity" {
    var directory = PeerLinkDirectory{};
    defer directory.deinit();
    for (0..MAX_PEER_LINKS) |index| {
        try directory.bind(
            .{ .kind = .device, .serial = @as(u64, @intCast(index + 1)) },
            .{ 0x02, 0x5A, 0x47, 0, 0, @as(u8, @intCast(index + 1)) },
        );
    }
    try std.testing.expectError(error.PeerLinkDirectoryFull, directory.bind(
        .{ .kind = .device, .serial = MAX_PEER_LINKS + 1 },
        .{ 0x02, 0x5A, 0x47, 0, 1, 1 },
    ));
    try std.testing.expectEqual(MAX_PEER_LINKS, directory.count());
    const last_device = principal.PrincipalId{ .kind = .device, .serial = MAX_PEER_LINKS };
    const last_mac = [_]u8{ 0x02, 0x5A, 0x47, 0, 0, MAX_PEER_LINKS };
    try std.testing.expectEqualSlices(u8, &last_mac, &directory.resolve(last_device).?);
}

test "network driver data plane is brokered by explicit egress capability" {
    const Harness = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;
        var last_frame: [MAX_NATIVE_FRAME_BYTES]u8 = undefined;
        const expected_destination = [_]u8{ 0x02, 0, 0, 0, 0, 0x41 };

        fn send(_: [6]u8, frame: []const u8) bool {
            send_count += 1;
            last_frame_len = frame.len;
            @memcpy(last_frame[0..frame.len], frame);
            return true;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 1 };
        }

        fn broker(request: EgressRequest) EgressDecision {
            return .{
                .allowed = request.network_policy_id == 41 and
                    std.mem.eql(u8, &request.destination_mac, &expected_destination),
                .capability_backed = request.egress_capability_id == 99,
            };
        }
    };

    reset();
    defer reset();
    Harness.send_count = 0;

    const device = NetworkDevice{
        .send = Harness.send,
        .receive = noNetworkFrame,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(activateDevice(&device, 7));
    const peer_mac = Harness.expected_destination;
    try std.testing.expect(!sendActiveFrame(@as([6]u8, @splat(0)), "frame"));
    try std.testing.expect(!sendActiveFrame(peer_mac, "frame"));
    setEgressBroker(Harness.broker);
    try std.testing.expect(!sendActiveFrame(peer_mac, "frame"));
    bindEgressCapability(99, 41);
    try std.testing.expect(!sendActiveFrame(peer_mac, &@as([MAX_NATIVE_FRAME_BYTES + 1]u8, @splat(0))));
    try std.testing.expect(sendActiveFrame(peer_mac, "frame"));
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
    try std.testing.expectEqual(@as(usize, 1), activeDriverTransmitCount());
    try std.testing.expectEqualStrings("frame", Harness.last_frame[0..Harness.last_frame_len]);
}

test "network transmit failure is reported without advancing ownership telemetry" {
    const Harness = struct {
        fn send(_: [6]u8, _: []const u8) bool {
            return false;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 2 };
        }

        fn broker(_: EgressRequest) EgressDecision {
            return .{ .allowed = true, .capability_backed = true };
        }
    };

    reset();
    defer reset();
    const device = NetworkDevice{
        .send = Harness.send,
        .receive = noNetworkFrame,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(activateDevice(&device, 8));
    setEgressBroker(Harness.broker);
    bindEgressCapability(100, 42);
    try std.testing.expect(!sendActiveFrame(.{ 0x02, 0, 0, 0, 0, 0x42 }, "frame"));
    try std.testing.expectEqual(@as(usize, 0), activeDriverTransmitCount());
}

test "network receive polling distinguishes empty drop failure and owned frame" {
    const Harness = struct {
        const Mode = enum { empty, frame, dropped, failed, malformed };
        var mode: Mode = .empty;

        fn send(_: [6]u8, _: []const u8) bool {
            return true;
        }

        fn receive(output: []u8) ReceiveResult {
            return switch (mode) {
                .empty => .{ .status = .empty },
                .frame => result: {
                    @memcpy(output[0..8], "ZGNPrecv");
                    break :result .{ .status = .frame, .length = 8 };
                },
                .dropped => .{ .status = .dropped },
                .failed => .{ .status = .failed },
                .malformed => .{ .status = .frame, .length = @intCast(output.len + 1) },
            };
        }

        fn workPending() bool {
            return true;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0, 0, 0, 0, 3 };
        }
    };

    reset();
    defer reset();
    Harness.mode = .empty;
    const device = NetworkDevice{
        .send = Harness.send,
        .receive = Harness.receive,
        .workPending = Harness.workPending,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(activateDevice(&device, 9));
    try std.testing.expect(acceptReceivePrefix("ZGNP".*));
    var output: [32]u8 = undefined;

    const empty = servicePendingReceiveFrames(4);
    try std.testing.expectEqual(@as(usize, 1), empty.polls);
    try std.testing.expect(!empty.failed);
    try std.testing.expectEqual(ReceiveStatus.empty, receiveQueuedFrame(&output).status);

    Harness.mode = .frame;
    try std.testing.expectEqual(@as(usize, 1), servicePendingReceiveFrames(1).frames_queued);
    const frame = receiveQueuedFrame(&output);
    try std.testing.expectEqual(ReceiveStatus.frame, frame.status);
    try std.testing.expectEqualStrings("ZGNPrecv", output[0..frame.length]);

    Harness.mode = .dropped;
    const dropped = servicePendingReceiveFrames(2);
    try std.testing.expectEqual(@as(usize, 2), dropped.dropped);
    try std.testing.expect(!dropped.failed);

    Harness.mode = .failed;
    try std.testing.expect(servicePendingReceiveFrames(2).failed);
    Harness.mode = .malformed;
    const malformed = servicePendingReceiveFrames(2);
    try std.testing.expect(malformed.failed);
    try std.testing.expectEqual(@as(usize, 1), malformed.polls);
    try std.testing.expect(!hasQueuedFrame());
}

test "pending network work is budgeted into the deferred receive queue" {
    const frames = [_][]const u8{ "ZGNP-0", "ZGNP-1", "ZGNP-2" };
    reset();
    defer reset();
    ReceiveHarness.start(&frames);
    try std.testing.expect(activateDeviceForTask(&ReceiveHarness.device, 10, 99));
    try std.testing.expect(acceptReceivePrefix("ZGNP".*));
    try std.testing.expectEqual(@as(u64, 99), activeTaskId());
    try std.testing.expect(networkWorkPending());

    const first_service = servicePendingReceiveFrames(2);
    try std.testing.expectEqual(@as(usize, 2), first_service.polls);
    try std.testing.expectEqual(@as(usize, 2), first_service.frames_queued);

    var output: [32]u8 = undefined;
    try std.testing.expectEqualStrings("ZGNP-0", output[0..receiveQueuedFrame(&output).length]);
    try std.testing.expectEqualStrings("ZGNP-1", output[0..receiveQueuedFrame(&output).length]);
    try std.testing.expect(!hasQueuedFrame());

    const second_service = servicePendingReceiveFrames(8);
    try std.testing.expectEqual(@as(usize, 1), second_service.frames_queued);
    try std.testing.expect(!networkWorkPending());
    try std.testing.expectEqualStrings("ZGNP-2", output[0..receiveQueuedFrame(&output).length]);
}

test "deferred receive queues only the registered consumer's frames" {
    const frames = [_][]const u8{ "before", "ZGNPpeer", "between", "ZGNPoversized-frame", "after" };
    reset();
    defer reset();
    try std.testing.expect(activateDevice(&ReceiveHarness.device, 10));
    try std.testing.expect(acceptReceivePrefix("ZGNP".*));
    try std.testing.expect(acceptReceivePrefix("ZGNP".*));
    var out: [16]u8 = undefined;
    for (0..RECEIVE_QUEUE_CAPACITY * 2) |_| {
        ReceiveHarness.start(&frames);
        const service = servicePendingReceiveFrames(frames.len);
        try std.testing.expectEqual(@as(usize, 2), service.frames_queued);
        try std.testing.expectEqual(@as(usize, 3), service.dropped);
        try std.testing.expect(hasQueuedFrame());
        try std.testing.expectEqualStrings("ZGNPpeer", out[0..receiveQueuedFrame(&out).length]);
        try std.testing.expectEqual(ReceiveStatus.dropped, receiveQueuedFrame(&out).status);
        try std.testing.expectEqual(ReceiveStatus.empty, receiveQueuedFrame(&out).status);
        try std.testing.expect(!hasQueuedFrame());
    }
}

test "receive without a registered consumer drains hardware without queuing" {
    const frames = [_][]const u8{ "ZGNParp", "ZGNPnd", "ZGNPbroadcast" };
    reset();
    defer reset();
    ReceiveHarness.start(&frames);
    try std.testing.expect(activateDevice(&ReceiveHarness.device, 12));
    const service = servicePendingReceiveFrames(frames.len + 1);
    try std.testing.expectEqual(@as(usize, 0), service.frames_queued);
    try std.testing.expectEqual(frames.len, service.dropped);
    try std.testing.expectEqual(frames.len, ReceiveHarness.empty_output_drains);
    try std.testing.expect(!hasQueuedFrame());
    try std.testing.expect(!networkWorkPending());
    try std.testing.expect(receiveQueue() == null);
}

test "deferred receive service drains hardware when the software queue is full" {
    var frames: [RECEIVE_QUEUE_CAPACITY + 1][]const u8 = @splat("ZGNPpacket");
    reset();
    defer reset();
    ReceiveHarness.start(&frames);
    try std.testing.expect(activateDevice(&ReceiveHarness.device, 11));
    try std.testing.expect(acceptReceivePrefix("ZGNP".*));
    const service = servicePendingReceiveFrames(frames.len);
    try std.testing.expectEqual(RECEIVE_QUEUE_CAPACITY, service.frames_queued);
    try std.testing.expectEqual(@as(usize, 1), service.dropped);
    try std.testing.expectEqual(@as(usize, 1), ReceiveHarness.empty_output_drains);
    try std.testing.expect(!networkWorkPending());

    var out: [16]u8 = undefined;
    for (0..RECEIVE_QUEUE_CAPACITY) |_| {
        try std.testing.expectEqualStrings("ZGNPpacket", out[0..receiveQueuedFrame(&out).length]);
    }
    try std.testing.expectEqual(ReceiveStatus.empty, receiveQueuedFrame(&out).status);
}

test "driver restart discards queued frames but keeps the consumer registration" {
    const frames = [_][]const u8{ "ZGNPstale", "ZGNPfresh" };
    reset();
    defer reset();
    ReceiveHarness.start(frames[0..1]);
    try std.testing.expect(activateDevice(&ReceiveHarness.device, 13));
    try std.testing.expect(acceptReceivePrefix("ZGNP".*));
    try std.testing.expectEqual(@as(usize, 1), servicePendingReceiveFrames(1).frames_queued);
    try std.testing.expect(deactivateDevice(13));
    try std.testing.expect(!hasQueuedFrame());

    ReceiveHarness.start(frames[1..]);
    try std.testing.expect(activateDevice(&ReceiveHarness.device, 13));
    try std.testing.expectEqual(@as(usize, 1), servicePendingReceiveFrames(1).frames_queued);
    var out: [16]u8 = undefined;
    try std.testing.expectEqualStrings("ZGNPfresh", out[0..receiveQueuedFrame(&out).length]);
}
