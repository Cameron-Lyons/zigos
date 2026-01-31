const ipv6 = @import("ipv6.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");
const timer = @import("../timer/timer.zig");

pub const ICMPv6Header = packed struct {
    icmp_type: u8,
    code: u8,
    checksum: u16,
};

const ICMPv6Type = struct {
    const EchoRequest: u8 = 128;
    const EchoReply: u8 = 129;
    const RouterSolicitation: u8 = 133;
    const RouterAdvertisement: u8 = 134;
    const NeighborSolicitation: u8 = 135;
    const NeighborAdvertisement: u8 = 136;
};

const NeighborState = enum {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
};

const NeighborEntry = struct {
    ipv6_addr: ipv6.IPv6Address,
    mac: [6]u8,
    state: NeighborState,
    timestamp: u64,
    valid: bool,
};

const MAX_NEIGHBORS = 64;
var neighbor_cache: [MAX_NEIGHBORS]NeighborEntry = [_]NeighborEntry{NeighborEntry{
    .ipv6_addr = ipv6.UNSPECIFIED,
    .mac = [_]u8{0} ** 6,
    .state = .Incomplete,
    .timestamp = 0,
    .valid = false,
}} ** MAX_NEIGHBORS;

var initialized: bool = false;

pub fn init() void {
    ipv6.registerProtocolHandler(ipv6.NEXT_HEADER_ICMPV6, handlePacket);
    initialized = true;
    vga.print("ICMPv6 initialized\n");
}

fn calculateChecksum(src: *const ipv6.IPv6Address, dst: *const ipv6.IPv6Address, data: []const u8) u16 {
    var sum: u32 = ipv6.calculatePseudoHeaderChecksum(src, dst, ipv6.NEXT_HEADER_ICMPV6, @intCast(data.len));

    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, data[i]) << 8 | data[i + 1];
    }
    if (data.len & 1 != 0) {
        sum += @as(u32, data[data.len - 1]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const result: u16 = @intCast(sum);
    return ~result;
}

fn handlePacket(src: *const ipv6.IPv6Address, dst: *const ipv6.IPv6Address, data: []const u8) void {
    _ = dst;

    if (data.len < @sizeOf(ICMPv6Header)) return;

    const header: *const ICMPv6Header = @ptrCast(@alignCast(data.ptr));

    switch (header.icmp_type) {
        ICMPv6Type.EchoRequest => {
            sendEchoReply(src, data);
        },
        ICMPv6Type.NeighborSolicitation => {
            if (data.len >= @sizeOf(ICMPv6Header) + 4 + 16) {
                handleNeighborSolicitation(src, data);
            }
        },
        ICMPv6Type.NeighborAdvertisement => {
            if (data.len >= @sizeOf(ICMPv6Header) + 4 + 16) {
                handleNeighborAdvertisement(src, data);
            }
        },
        ICMPv6Type.RouterAdvertisement => {},
        else => {},
    }
}

fn sendEchoReply(dst: *const ipv6.IPv6Address, request_data: []const u8) void {
    if (request_data.len < 8) return;

    const reply_size = request_data.len;
    // SAFETY: fully written before sending
    var reply_buf: [1280]u8 = undefined;
    if (reply_size > reply_buf.len) return;

    @memcpy(reply_buf[0..reply_size], request_data[0..reply_size]);

    reply_buf[0] = ICMPv6Type.EchoReply;
    reply_buf[2] = 0;
    reply_buf[3] = 0;

    const src = ipv6.getLinkLocalAddress();
    const checksum = calculateChecksum(&src, dst, reply_buf[0..reply_size]);
    reply_buf[2] = @intCast((checksum >> 8) & 0xFF);
    reply_buf[3] = @intCast(checksum & 0xFF);

    ipv6.sendPacket(dst.*, ipv6.NEXT_HEADER_ICMPV6, reply_buf[0..reply_size]);
}

pub fn sendNeighborSolicitation(target: ipv6.IPv6Address) void {
    const msg_size: usize = @sizeOf(ICMPv6Header) + 4 + 16 + 8;
    // SAFETY: fully written before sending
    var buf: [48]u8 = undefined;

    buf[0] = ICMPv6Type.NeighborSolicitation;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;

    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;

    @memcpy(buf[8..24], &target.octets);

    buf[24] = 1;
    buf[25] = 1;

    const src = ipv6.getLinkLocalAddress();
    @memcpy(buf[26..32], src.octets[10..16]);

    const sol_node = solicitedNodeMulticast(&target);

    const checksum = calculateChecksum(&src, &sol_node, buf[0..msg_size]);
    buf[2] = @intCast((checksum >> 8) & 0xFF);
    buf[3] = @intCast(checksum & 0xFF);

    ipv6.sendPacket(sol_node, ipv6.NEXT_HEADER_ICMPV6, buf[0..msg_size]);
}

fn handleNeighborSolicitation(src: *const ipv6.IPv6Address, data: []const u8) void {
    const target_offset: usize = @sizeOf(ICMPv6Header) + 4;
    if (data.len < target_offset + 16) return;

    var target: ipv6.IPv6Address = undefined;
    @memcpy(&target.octets, data[target_offset .. target_offset + 16]);

    const our_addr = ipv6.getLinkLocalAddress();
    if (!our_addr.eql(&target)) return;

    sendNeighborAdvertisement(src, &target);
}

fn sendNeighborAdvertisement(dst: *const ipv6.IPv6Address, target: *const ipv6.IPv6Address) void {
    const msg_size: usize = @sizeOf(ICMPv6Header) + 4 + 16 + 8;
    // SAFETY: fully written before sending
    var buf: [48]u8 = undefined;

    buf[0] = ICMPv6Type.NeighborAdvertisement;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;

    buf[4] = 0x60;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;

    @memcpy(buf[8..24], &target.octets);

    buf[24] = 2;
    buf[25] = 1;

    const src = ipv6.getLinkLocalAddress();
    @memcpy(buf[26..32], src.octets[10..16]);

    const checksum = calculateChecksum(&src, dst, buf[0..msg_size]);
    buf[2] = @intCast((checksum >> 8) & 0xFF);
    buf[3] = @intCast(checksum & 0xFF);

    ipv6.sendPacket(dst.*, ipv6.NEXT_HEADER_ICMPV6, buf[0..msg_size]);
}

fn handleNeighborAdvertisement(src: *const ipv6.IPv6Address, data: []const u8) void {
    const target_offset: usize = @sizeOf(ICMPv6Header) + 4;
    if (data.len < target_offset + 16) return;

    var target: ipv6.IPv6Address = undefined;
    @memcpy(&target.octets, data[target_offset .. target_offset + 16]);

    const opt_offset = target_offset + 16;
    if (data.len >= opt_offset + 8 and data[opt_offset] == 2 and data[opt_offset + 1] == 1) {
        var mac: [6]u8 = undefined;
        @memcpy(&mac, data[opt_offset + 2 .. opt_offset + 8]);
        updateNeighborCache(src, mac);
    }
}

fn updateNeighborCache(addr: *const ipv6.IPv6Address, mac: [6]u8) void {
    for (&neighbor_cache) |*entry| {
        if (entry.valid and entry.ipv6_addr.eql(addr)) {
            entry.mac = mac;
            entry.state = .Reachable;
            entry.timestamp = timer.getTicks();
            return;
        }
    }

    for (&neighbor_cache) |*entry| {
        if (!entry.valid) {
            entry.ipv6_addr = addr.*;
            entry.mac = mac;
            entry.state = .Reachable;
            entry.timestamp = timer.getTicks();
            entry.valid = true;
            return;
        }
    }

    var oldest_idx: usize = 0;
    var oldest_time: u64 = neighbor_cache[0].timestamp;
    for (neighbor_cache, 0..) |entry, i| {
        if (entry.timestamp < oldest_time) {
            oldest_time = entry.timestamp;
            oldest_idx = i;
        }
    }

    neighbor_cache[oldest_idx] = NeighborEntry{
        .ipv6_addr = addr.*,
        .mac = mac,
        .state = .Reachable,
        .timestamp = timer.getTicks(),
        .valid = true,
    };
}

pub fn resolveNeighbor(addr: *const ipv6.IPv6Address) ?[6]u8 {
    for (neighbor_cache) |entry| {
        if (entry.valid and entry.ipv6_addr.eql(addr)) {
            return entry.mac;
        }
    }

    sendNeighborSolicitation(addr.*);
    return null;
}

fn solicitedNodeMulticast(addr: *const ipv6.IPv6Address) ipv6.IPv6Address {
    var sol = ipv6.IPv6Address{ .octets = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0, 0, 0 } };
    sol.octets[13] = addr.octets[13];
    sol.octets[14] = addr.octets[14];
    sol.octets[15] = addr.octets[15];
    return sol;
}
