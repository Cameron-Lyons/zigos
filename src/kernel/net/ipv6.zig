const ethernet = @import("ethernet.zig");
const icmpv6 = @import("icmpv6.zig");
const rtl8139 = @import("../drivers/rtl8139.zig");
const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");

pub const NEXT_HEADER_TCP: u8 = 6;
pub const NEXT_HEADER_UDP: u8 = 17;
pub const NEXT_HEADER_ICMPV6: u8 = 58;

pub const IPv6Address = struct {
    octets: [16]u8,

    pub fn isZero(self: *const IPv6Address) bool {
        for (self.octets) |b| {
            if (b != 0) return false;
        }
        return true;
    }

    pub fn eql(self: *const IPv6Address, other: *const IPv6Address) bool {
        for (self.octets, other.octets) |a, b| {
            if (a != b) return false;
        }
        return true;
    }

    pub fn isLinkLocal(self: *const IPv6Address) bool {
        return self.octets[0] == 0xFE and (self.octets[1] & 0xC0) == 0x80;
    }

    pub fn isMulticast(self: *const IPv6Address) bool {
        return self.octets[0] == 0xFF;
    }
};

pub const IPv6Header = extern struct {
    version_tc_flow: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    src: [16]u8,
    dst: [16]u8,
};

pub const UNSPECIFIED = IPv6Address{ .octets = [_]u8{0} ** 16 };
pub const LOOPBACK = IPv6Address{ .octets = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
pub const ALL_NODES_MULTICAST = IPv6Address{ .octets = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
pub const ALL_ROUTERS_MULTICAST = IPv6Address{ .octets = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 } };

var link_local_addr: IPv6Address = undefined;
var global_addr: IPv6Address = .{ .octets = [_]u8{0} ** 16 };
var has_global_addr: bool = false;
var default_gateway: IPv6Address = .{ .octets = [_]u8{0} ** 16 };
var has_default_gateway: bool = false;
var initialized: bool = false;

const ProtocolHandler = fn (src: *const IPv6Address, dst: *const IPv6Address, data: []const u8) void;
var tcp_handler: ?*const ProtocolHandler = null;
var udp_handler: ?*const ProtocolHandler = null;
var icmpv6_handler: ?*const ProtocolHandler = null;

pub fn init() void {
    if (rtl8139.getMACAddress()) |mac| {
        link_local_addr = generateLinkLocal(mac);
        vga.print("IPv6 link-local: fe80::");
        printHexByte(mac[0] ^ 0x02);
        printHexByte(mac[1]);
        vga.print(":");
        printHexByte(mac[2]);
        vga.print("ff:fe");
        printHexByte(mac[3]);
        vga.print(":");
        printHexByte(mac[4]);
        printHexByte(mac[5]);
        vga.print("\n");
    } else {
        @memset(&link_local_addr.octets, 0);
        link_local_addr.octets[0] = 0xFE;
        link_local_addr.octets[1] = 0x80;
        link_local_addr.octets[15] = 1;
    }

    ethernet.registerHandler(.IPv6, handleEthernetFrame);
    initialized = true;
    vga.print("IPv6 initialized\n");
}

fn generateLinkLocal(mac: [6]u8) IPv6Address {
    var addr = IPv6Address{ .octets = [_]u8{0} ** 16 };
    addr.octets[0] = 0xFE;
    addr.octets[1] = 0x80;

    addr.octets[8] = mac[0] ^ 0x02;
    addr.octets[9] = mac[1];
    addr.octets[10] = mac[2];
    addr.octets[11] = 0xFF;
    addr.octets[12] = 0xFE;
    addr.octets[13] = mac[3];
    addr.octets[14] = mac[4];
    addr.octets[15] = mac[5];

    return addr;
}

pub fn registerProtocolHandler(next_header: u8, handler: *const ProtocolHandler) void {
    switch (next_header) {
        NEXT_HEADER_TCP => tcp_handler = handler,
        NEXT_HEADER_UDP => udp_handler = handler,
        NEXT_HEADER_ICMPV6 => icmpv6_handler = handler,
        else => {},
    }
}

pub fn sendPacket(dst: IPv6Address, next_header: u8, payload: []const u8) void {
    if (!initialized) return;
    if (payload.len > ethernet.ETH_MTU - @sizeOf(IPv6Header)) return;

    const total_size = @sizeOf(IPv6Header) + payload.len;
    // SAFETY: header and payload portions filled before the buffer is sent
    var packet_buf: [ethernet.ETH_MTU]u8 = undefined;

    const header: *IPv6Header = @ptrCast(@alignCast(&packet_buf[0]));
    header.version_tc_flow = @byteSwap(@as(u32, 0x60000000));
    header.payload_length = @byteSwap(@as(u16, @intCast(payload.len)));
    header.next_header = next_header;
    header.hop_limit = 64;
    const src_addr = getSourceAddress(&dst);
    header.src = src_addr.octets;
    header.dst = dst.octets;

    @memcpy(packet_buf[@sizeOf(IPv6Header) .. @sizeOf(IPv6Header) + payload.len], payload);

    const dst_mac = resolveIPv6ToMAC(&dst);
    ethernet.sendFrame(dst_mac, .IPv6, packet_buf[0..total_size]) catch {};
}

fn resolveIPv6ToMAC(addr: *const IPv6Address) [6]u8 {
    if (addr.isMulticast()) {
        return .{ 0x33, 0x33, addr.octets[12], addr.octets[13], addr.octets[14], addr.octets[15] };
    }
    if (icmpv6.resolveNeighbor(addr)) |mac| {
        return mac;
    }
    return .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
}

fn handleEthernetFrame(frame: *const ethernet.EthernetFrame) void {
    handlePacket(frame.data);
}

pub fn handlePacket(data: []const u8) void {
    if (data.len < @sizeOf(IPv6Header)) return;

    const header: *const IPv6Header = @ptrCast(@alignCast(data.ptr));

    const version_tc_flow = @byteSwap(header.version_tc_flow);
    const version = (version_tc_flow >> 28) & 0xF;
    if (version != 6) return;

    const payload_length = @byteSwap(header.payload_length);
    if (@as(usize, @sizeOf(IPv6Header)) + payload_length > data.len) return;

    const payload = data[@sizeOf(IPv6Header) .. @sizeOf(IPv6Header) + payload_length];
    const src = IPv6Address{ .octets = header.src };
    const dst = IPv6Address{ .octets = header.dst };

    switch (header.next_header) {
        NEXT_HEADER_TCP => {
            if (tcp_handler) |handler| handler(&src, &dst, payload);
        },
        NEXT_HEADER_UDP => {
            if (udp_handler) |handler| handler(&src, &dst, payload);
        },
        NEXT_HEADER_ICMPV6 => {
            if (icmpv6_handler) |handler| handler(&src, &dst, payload);
        },
        else => {},
    }
}

pub fn getLinkLocalAddress() IPv6Address {
    return link_local_addr;
}

pub fn getGlobalAddress() ?IPv6Address {
    if (has_global_addr) return global_addr;
    return null;
}

pub fn setGlobalAddress(addr: IPv6Address) void {
    global_addr = addr;
    has_global_addr = true;
    vga.print("IPv6 global address configured\n");
}

pub fn setDefaultGateway(addr: IPv6Address) void {
    default_gateway = addr;
    has_default_gateway = true;
    vga.print("IPv6 default gateway configured\n");
}

pub fn getSourceAddress(dst: *const IPv6Address) IPv6Address {
    if (dst.isLinkLocal()) return link_local_addr;
    if (has_global_addr) return global_addr;
    return link_local_addr;
}

pub fn calculatePseudoHeaderChecksum(src: *const IPv6Address, dst: *const IPv6Address, next_header: u8, payload_length: u16) u32 {
    var sum: u32 = 0;

    var i: usize = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u32, src.octets[i]) << 8 | src.octets[i + 1];
        sum += @as(u32, dst.octets[i]) << 8 | dst.octets[i + 1];
    }

    sum += payload_length;
    sum += next_header;

    return sum;
}

fn printHexByte(b: u8) void {
    const hex_chars = "0123456789abcdef";
    vga.printChar(hex_chars[(b >> 4) & 0xF]);
    vga.printChar(hex_chars[b & 0xF]);
}
