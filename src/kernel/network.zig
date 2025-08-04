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
    
    // Initialize layers bottom-up
    ethernet.init();
    arp.init();
    ipv4.init();
    icmp.init();
    tcp.init();
    udp.init();
    
    vga.print("Network stack initialized!\n");
}

// Handle incoming packets from the network driver
pub fn handleRxPacket(packet: []u8) void {
    ethernet.handleRxPacket(packet);
}

// Utility function to parse IP address string
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

// Format IP address for display
pub fn formatIPv4(ip: u32, buf: []u8) []u8 {
    const a = (ip >> 24) & 0xFF;
    const b = (ip >> 16) & 0xFF;
    const c = (ip >> 8) & 0xFF;
    const d = ip & 0xFF;
    
    const len = std.fmt.formatIntBuf(buf[0..], a, 10, .lower, .{});
    buf[len] = '.';
    const len2 = std.fmt.formatIntBuf(buf[len + 1..], b, 10, .lower, .{});
    buf[len + 1 + len2] = '.';
    const len3 = std.fmt.formatIntBuf(buf[len + 1 + len2 + 1..], c, 10, .lower, .{});
    buf[len + 1 + len2 + 1 + len3] = '.';
    const len4 = std.fmt.formatIntBuf(buf[len + 1 + len2 + 1 + len3 + 1..], d, 10, .lower, .{});
    
    return buf[0..len + 1 + len2 + 1 + len3 + 1 + len4];
}

// Test function to send a ping
pub fn ping(dst_ip: u32) void {
    const data = "Hello from ZigOS!";
    icmp.sendEchoRequest(dst_ip, 1, 1, data) catch |err| {
        vga.print("Ping failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
}