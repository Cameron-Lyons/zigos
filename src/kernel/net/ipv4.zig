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
    header: *align(1) const IPv4Header,
    data: []u8,
};

var rx_handlers: [3]?*const fn (packet: *const IPv4Packet) void = [_]?*const fn (packet: *const IPv4Packet) void{null} ** 3;

const DEFAULT_LOCAL_IP: u32 = 0x0A000002;
const DEFAULT_GATEWAY_IP: u32 = 0x0A000001;
const DEFAULT_NETMASK: u32 = 0xFFFFFF00;

var local_ip: u32 = DEFAULT_LOCAL_IP;
var gateway_ip: u32 = DEFAULT_GATEWAY_IP;
var netmask: u32 = DEFAULT_NETMASK;

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

    const header: *align(1) const IPv4Header = @ptrCast(frame.data.ptr);

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
    if (dst_ip != local_ip and dst_ip != 0xFFFFFFFF) {
        return;
    }

    const packet = IPv4Packet{
        .header = header,
        .data = frame.data[ihl..],
    };

    // SAFETY: assigned in every branch of the if/else chain below; function returns on else
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
    // SAFETY: all fields assigned before the struct is used
    var header: IPv4Header = undefined;
    const src_ip = if (isLoopbackAddress(dst_ip)) dst_ip else local_ip;

    header.version_ihl = (IP_VERSION_4 << 4) | 5;
    header.tos = 0;
    header.total_length = @byteSwap(@as(u16, @intCast(IP_HEADER_MIN_SIZE + data.len)));
    header.identification = @byteSwap(@as(u16, 0));
    header.flags_fragment = @byteSwap(@as(u16, 0x4000));
    header.ttl = 64;
    header.protocol = @intFromEnum(protocol);
    header.checksum = 0;
    header.src_addr = @byteSwap(src_ip);
    header.dst_addr = @byteSwap(dst_ip);

    header.checksum = calculateChecksum(&header, IP_HEADER_MIN_SIZE);

    if (isLoopbackAddress(dst_ip)) {
        dispatchLocalPacket(protocol, &header, data);
        return;
    }

    if (dst_ip == 0xFFFFFFFF) {
        var packet_buf: [1500]u8 = undefined;
        const header_ptr: [*]const u8 = @ptrCast(&header);
        @memcpy(packet_buf[0..IP_HEADER_MIN_SIZE], header_ptr[0..IP_HEADER_MIN_SIZE]);
        @memcpy(packet_buf[IP_HEADER_MIN_SIZE .. IP_HEADER_MIN_SIZE + data.len], data);
        try ethernet.sendFrame([_]u8{0xFF} ** 6, .IPv4, packet_buf[0 .. IP_HEADER_MIN_SIZE + data.len]);
        return;
    }

    const next_hop = if (isLocalNetwork(dst_ip)) dst_ip else gateway_ip;

    // SAFETY: assigned from arp.resolve result or function returns on failure
    var dst_mac: [6]u8 = undefined;
    if (arp.resolve(next_hop)) |mac| {
        dst_mac = mac;
    } else {
        try arp.sendARPRequest(next_hop);
        return error.ARPResolutionFailed;
    }

    // SAFETY: filled by the subsequent memcpy calls for header and data
    var packet_buf: [1500]u8 = undefined;
    const header_ptr: [*]const u8 = @ptrCast(&header);
    @memcpy(packet_buf[0..IP_HEADER_MIN_SIZE], header_ptr[0..IP_HEADER_MIN_SIZE]);
    @memcpy(packet_buf[IP_HEADER_MIN_SIZE .. IP_HEADER_MIN_SIZE + data.len], data);

    try ethernet.sendFrame(dst_mac, .IPv4, packet_buf[0 .. IP_HEADER_MIN_SIZE + data.len]);
}

fn dispatchLocalPacket(protocol: Protocol, header: *const IPv4Header, data: []const u8) void {
    const packet = IPv4Packet{
        .header = header,
        .data = @constCast(data),
    };

    const handler_index: usize = switch (protocol) {
        .ICMP => 0,
        .TCP => 1,
        .UDP => 2,
    };
    if (rx_handlers[handler_index]) |handler| {
        handler(&packet);
    }
}

fn calculateChecksum(header: *const IPv4Header, len: usize) u16 {
    var sum: u32 = 0;
    const data: [*]const u16 = @ptrCast(@alignCast(header));
    const word_count = len / 2;

    var i: usize = 0;
    while (i < word_count) : (i += 1) {
        sum += data[i];
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const result: u16 = @truncate(~sum);
    return result;
}

fn verifyChecksum(header: *align(1) const IPv4Header, len: usize) bool {
    var sum: u32 = 0;
    const data: [*]const u16 = @ptrCast(@alignCast(header));
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
    return (ip & netmask) == (local_ip & netmask);
}

fn isLoopbackAddress(ip: u32) bool {
    return (ip & 0xFF000000) == 0x7F000000;
}

pub fn registerProtocolHandler(protocol: u8, handler: fn (src_ip: u32, dst_ip: u32, data: []const u8) void) void {
    const handler_ptr: *const fn (packet: *const IPv4Packet) void = @ptrCast(&struct {
        fn wrapper(packet: *const IPv4Packet) void {
            const src_ip = @byteSwap(packet.header.src_addr);
            const dst_ip = @byteSwap(packet.header.dst_addr);
            handler(src_ip, dst_ip, packet.data);
        }
    }.wrapper);

    if (protocol == @intFromEnum(Protocol.TCP)) {
        rx_handlers[1] = handler_ptr;
    } else if (protocol == @intFromEnum(Protocol.UDP)) {
        rx_handlers[2] = handler_ptr;
    }
}

pub fn getLocalIP() u32 {
    return local_ip;
}

pub fn getLocalAddress() IPv4Address {
    return IPv4Address.fromU32(local_ip);
}

pub fn setLocalIP(ip: u32) void {
    local_ip = ip;
}

pub fn setLocalAddress(ip: IPv4Address) void {
    local_ip = ip.toU32();
}

pub fn getGatewayIP() u32 {
    return gateway_ip;
}

pub fn getGatewayAddress() IPv4Address {
    return IPv4Address.fromU32(gateway_ip);
}

pub fn setGatewayIP(ip: u32) void {
    gateway_ip = ip;
}

pub fn setGatewayAddress(ip: IPv4Address) void {
    gateway_ip = ip.toU32();
}

pub fn getNetmask() u32 {
    return netmask;
}

pub fn getNetmaskAddress() IPv4Address {
    return IPv4Address.fromU32(netmask);
}

pub fn setNetmask(mask: u32) void {
    netmask = mask;
}

pub fn setNetmaskAddress(mask: IPv4Address) void {
    netmask = mask.toU32();
}
