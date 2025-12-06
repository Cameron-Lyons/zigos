const std = @import("std");
const vga = @import("../drivers/vga.zig");
const ethernet = @import("ethernet.zig");
const arp = @import("arp.zig");

pub const IP_HEADER_MIN_SIZE = 20;
pub const IP_VERSION_4 = 4;

pub const Protocol = enum(u8) {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
};

pub const IPv4Address = struct {
    octets: [4]u8,

    pub fn toU32(self: IPv4Address) u32 {
        return (@as(u32, self.octets[0]) << 24) |
            (@as(u32, self.octets[1]) << 16) |
            (@as(u32, self.octets[2]) << 8) |
            self.octets[3];
    }

    pub fn fromU32(ip: u32) IPv4Address {
        return IPv4Address{
            .octets = .{
                @intCast((ip >> 24) & 0xFF),
                @intCast((ip >> 16) & 0xFF),
                @intCast((ip >> 8) & 0xFF),
                @intCast(ip & 0xFF),
            },
        };
    }
};

pub const IPv4Header = packed struct {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
};

pub const IPv4Packet = struct {
    header: *const IPv4Header,
    data: []u8,
};

var rx_handlers: [3]?*const fn (packet: *const IPv4Packet) void = [_]?*const fn (packet: *const IPv4Packet) void{null} ** 3;

pub const our_ip: u32 = 0xC0A80102;
pub const gateway_ip: u32 = 0xC0A80101;

pub fn init() void {
    ethernet.registerHandler(.IPv4, handleIPv4Packet);
    vga.print("IPv4 initialized\n");
}

pub fn registerHandler(protocol: Protocol, handler: *const fn (packet: *const IPv4Packet) void) void {
    const index: usize = switch (protocol) {
        .ICMP => 0,
        .TCP => 1,
        .UDP => 2,
    };
    rx_handlers[index] = handler;
}

fn handleIPv4Packet(frame: *const ethernet.EthernetFrame) void {
    if (frame.data.len < IP_HEADER_MIN_SIZE) {
        return;
    }

    const header = @as(*const IPv4Header, @ptrCast(@alignCast(frame.data.ptr)));

    const version = (header.version_ihl >> 4) & 0xF;
    if (version != IP_VERSION_4) {
        return;
    }

    const ihl = (header.version_ihl & 0xF) * 4;
    if (ihl < IP_HEADER_MIN_SIZE or ihl > frame.data.len) {
        return;
    }

    if (!verifyChecksum(header, ihl)) {
        return;
    }

    const dst_ip = @byteSwap(header.dst_addr);
    if (dst_ip != our_ip and dst_ip != 0xFFFFFFFF) {
        return;
    }

    const packet = IPv4Packet{
        .header = header,
        .data = frame.data[ihl..],
    };

    var handler_index: usize = undefined;
    if (header.protocol == @intFromEnum(Protocol.ICMP)) {
        handler_index = 0;
    } else if (header.protocol == @intFromEnum(Protocol.TCP)) {
        handler_index = 1;
    } else if (header.protocol == @intFromEnum(Protocol.UDP)) {
        handler_index = 2;
    } else {
        return;
    }

    if (handler_index < rx_handlers.len) {
        if (rx_handlers[handler_index]) |handler| {
            handler(&packet);
        }
    }
}

pub fn sendPacket(dst_ip: u32, protocol: Protocol, data: []const u8) !void {
    var header: IPv4Header = undefined;

    header.version_ihl = (IP_VERSION_4 << 4) | 5;
    header.tos = 0;
    header.total_length = @byteSwap(@as(u16, @intCast(IP_HEADER_MIN_SIZE + data.len)));
    header.identification = @byteSwap(@as(u16, 0));
    header.flags_fragment = @byteSwap(@as(u16, 0x4000));
    header.ttl = 64;
    header.protocol = @intFromEnum(protocol);
    header.checksum = 0;
    header.src_addr = @byteSwap(our_ip);
    header.dst_addr = @byteSwap(dst_ip);

    header.checksum = calculateChecksum(&header, IP_HEADER_MIN_SIZE);

    const next_hop = if (isLocalNetwork(dst_ip)) dst_ip else gateway_ip;

    var dst_mac: [6]u8 = undefined;
    if (arp.resolve(next_hop)) |mac| {
        dst_mac = mac;
    } else {
        try arp.sendARPRequest(next_hop);
        return error.ARPResolutionFailed;
    }

    var packet_buf: [1500]u8 = undefined;
    @memcpy(packet_buf[0..IP_HEADER_MIN_SIZE], @as([*]const u8, @ptrCast(&header))[0..IP_HEADER_MIN_SIZE]);
    @memcpy(packet_buf[IP_HEADER_MIN_SIZE .. IP_HEADER_MIN_SIZE + data.len], data);

    try ethernet.sendFrame(dst_mac, .IPv4, packet_buf[0 .. IP_HEADER_MIN_SIZE + data.len]);
}

fn calculateChecksum(header: *const IPv4Header, len: usize) u16 {
    var sum: u32 = 0;
    const data = @as([*]const u16, @ptrCast(@alignCast(header)));
    const word_count = len / 2;

    var i: usize = 0;
    while (i < word_count) : (i += 1) {
        sum += data[i];
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @as(u16, @intCast(~sum));
}

fn verifyChecksum(header: *const IPv4Header, len: usize) bool {
    var sum: u32 = 0;
    const data = @as([*]const u16, @ptrCast(@alignCast(header)));
    const word_count = len / 2;

    var i: usize = 0;
    while (i < word_count) : (i += 1) {
        sum += data[i];
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum == 0xFFFF;
}

fn isLocalNetwork(ip: u32) bool {
    return (ip & 0xFFFFFF00) == (our_ip & 0xFFFFFF00);
}

pub fn registerProtocolHandler(protocol: u8, handler: fn (src_ip: u32, dst_ip: u32, data: []const u8) void) void {
    const handler_ptr = @as(*const fn (packet: *const IPv4Packet) void, @ptrCast(&struct {
        fn wrapper(packet: *const IPv4Packet) void {
            const src_ip = @byteSwap(packet.header.src_addr);
            const dst_ip = @byteSwap(packet.header.dst_addr);
            handler(src_ip, dst_ip, packet.data);
        }
    }.wrapper));

    if (protocol == @intFromEnum(Protocol.TCP)) {
        rx_handlers[1] = handler_ptr;
    } else if (protocol == @intFromEnum(Protocol.UDP)) {
        rx_handlers[2] = handler_ptr;
    }
}

pub fn getLocalIP() u32 {
    return our_ip;
}

