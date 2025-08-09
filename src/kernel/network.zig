const std = @import("std");
const vga = @import("vga.zig");
const rtl8139 = @import("rtl8139.zig");
const ethernet = @import("ethernet.zig");
const arp = @import("arp.zig");
const ipv4 = @import("ipv4.zig");
const icmp = @import("icmp.zig");
const tcp = @import("tcp.zig");
const udp = @import("udp.zig");

pub fn init() void {
    vga.print("Initializing network stack...\n");

    ethernet.init();
    arp.init();
    ipv4.init();
    icmp.init();
    tcp.init();
    udp.init();

    vga.print("Network stack initialized!\n");
}

pub fn handleRxPacket(packet: []u8) void {
    ethernet.handleRxPacket(packet);
}

var local_ip: u32 = 0x0A000002; // 10.0.0.2
var gateway_ip: u32 = 0x0A000001; // 10.0.0.1
var netmask: u32 = 0xFFFFFF00; // 255.255.255.0

pub fn getLocalIP() ipv4.IPv4Address {
    return ipv4.IPv4Address{
        .octets = .{
            @intCast((local_ip >> 24) & 0xFF),
            @intCast((local_ip >> 16) & 0xFF),
            @intCast((local_ip >> 8) & 0xFF),
            @intCast(local_ip & 0xFF),
        },
    };
}

pub fn getGateway() ipv4.IPv4Address {
    return ipv4.IPv4Address{
        .octets = .{
            @intCast((gateway_ip >> 24) & 0xFF),
            @intCast((gateway_ip >> 16) & 0xFF),
            @intCast((gateway_ip >> 8) & 0xFF),
            @intCast(gateway_ip & 0xFF),
        },
    };
}

pub fn getGatewayIP() u32 {
    return gateway_ip;
}

pub fn getNetmask() ipv4.IPv4Address {
    return ipv4.IPv4Address{
        .octets = .{
            @intCast((netmask >> 24) & 0xFF),
            @intCast((netmask >> 16) & 0xFF),
            @intCast((netmask >> 8) & 0xFF),
            @intCast(netmask & 0xFF),
        },
    };
}

pub fn setLocalIP(ip: ipv4.IPv4Address) void {
    local_ip = (@as(u32, ip.octets[0]) << 24) |
        (@as(u32, ip.octets[1]) << 16) |
        (@as(u32, ip.octets[2]) << 8) |
        ip.octets[3];
}

pub fn setGateway(ip: ipv4.IPv4Address) void {
    gateway_ip = (@as(u32, ip.octets[0]) << 24) |
        (@as(u32, ip.octets[1]) << 16) |
        (@as(u32, ip.octets[2]) << 8) |
        ip.octets[3];
}

pub fn setGatewayIP(ip: u32) void {
    gateway_ip = ip;
}

pub fn setNetmask(mask: ipv4.IPv4Address) void {
    netmask = (@as(u32, mask.octets[0]) << 24) |
        (@as(u32, mask.octets[1]) << 16) |
        (@as(u32, mask.octets[2]) << 8) |
        mask.octets[3];
}

pub fn printIPv4(ip: ipv4.IPv4Address) void {
    printNumber(ip.octets[0]);
    vga.put_char('.');
    printNumber(ip.octets[1]);
    vga.put_char('.');
    printNumber(ip.octets[2]);
    vga.put_char('.');
    printNumber(ip.octets[3]);
}

fn printNumber(num: u32) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[count] = @intCast('0' + (n % 10));
        count += 1;
    }

    var i = count;
    while (i > 0) {
        i -= 1;
        vga.put_char(digits[i]);
    }
}

pub fn parseIPv4(str: []const u8) ?u32 {
    var ip: u32 = 0;
    var octet: u32 = 0;
    var octet_count: u8 = 0;

    for (str) |c| {
        if (c == '.') {
            if (octet > 255 or octet_count >= 3) {
                return null;
            }
            ip = (ip << 8) | octet;
            octet = 0;
            octet_count += 1;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            if (octet > 255) {
                return null;
            }
        } else {
            return null;
        }
    }

    if (octet_count != 3 or octet > 255) {
        return null;
    }

    return (ip << 8) | octet;
}

pub fn formatIPv4(ip: u32, buf: []u8) []u8 {
    const a = (ip >> 24) & 0xFF;
    const b = (ip >> 16) & 0xFF;
    const c = (ip >> 8) & 0xFF;
    const d = ip & 0xFF;

    const len = std.fmt.formatIntBuf(buf[0..], a, 10, .lower, .{});
    buf[len] = '.';
    const len2 = std.fmt.formatIntBuf(buf[len + 1 ..], b, 10, .lower, .{});
    buf[len + 1 + len2] = '.';
    const len3 = std.fmt.formatIntBuf(buf[len + 1 + len2 + 1 ..], c, 10, .lower, .{});
    buf[len + 1 + len2 + 1 + len3] = '.';
    const len4 = std.fmt.formatIntBuf(buf[len + 1 + len2 + 1 + len3 + 1 ..], d, 10, .lower, .{});

    return buf[0 .. len + 1 + len2 + 1 + len3 + 1 + len4];
}

pub fn ping(dst_ip: u32) void {
    const data = "Hello from ZigOS!";
    icmp.sendEchoRequest(dst_ip, 1, 1, data) catch |err| {
        vga.print("Ping failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
}

