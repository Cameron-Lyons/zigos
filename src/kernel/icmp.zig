const std = @import("std");
const vga = @import("vga.zig");
const ipv4 = @import("ipv4.zig");

const ICMP_TYPE_ECHO_REPLY = 0;
const ICMP_TYPE_ECHO_REQUEST = 8;

pub const ICMPHeader = packed struct {
    type: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
};

pub fn init() void {
    ipv4.registerHandler(.ICMP, handleICMPPacket);
    vga.print("ICMP initialized\n");
}

fn handleICMPPacket(packet: *const ipv4.IPv4Packet) void {
    if (packet.data.len < @sizeOf(ICMPHeader)) {
        return;
    }

    const header = @as(*const ICMPHeader, @ptrCast(@alignCast(packet.data.ptr)));

    if (!verifyChecksum(packet.data)) {
        return;
    }

    if (header.type == ICMP_TYPE_ECHO_REQUEST and header.code == 0) {
        sendEchoReply(packet, header);
    }
}

fn sendEchoReply(request_packet: *const ipv4.IPv4Packet, request_header: *const ICMPHeader) void {
    var reply_buf: [1500]u8 = undefined;
    var reply_header = @as(*ICMPHeader, @ptrCast(@alignCast(&reply_buf[0])));

    reply_header.type = ICMP_TYPE_ECHO_REPLY;
    reply_header.code = 0;
    reply_header.checksum = 0;
    reply_header.identifier = request_header.identifier;
    reply_header.sequence = request_header.sequence;

    const data_len = request_packet.data.len - @sizeOf(ICMPHeader);
    if (data_len > 0 and data_len < reply_buf.len - @sizeOf(ICMPHeader)) {
        @memcpy(reply_buf[@sizeOf(ICMPHeader) .. @sizeOf(ICMPHeader) + data_len], request_packet.data[@sizeOf(ICMPHeader)..]);
    }

    const total_len = @sizeOf(ICMPHeader) + data_len;
    reply_header.checksum = calculateChecksum(reply_buf[0..total_len]);

    const src_ip = @byteSwap(request_packet.header.src_addr);
    ipv4.sendPacket(src_ip, .ICMP, reply_buf[0..total_len]) catch {
        vga.print("Failed to send ICMP reply\n");
    };
}

pub fn sendEchoRequest(dst_ip: u32, identifier: u16, sequence: u16, data: []const u8) !void {
    var request_buf: [1500]u8 = undefined;
    var header = @as(*ICMPHeader, @ptrCast(@alignCast(&request_buf[0])));

    header.type = ICMP_TYPE_ECHO_REQUEST;
    header.code = 0;
    header.checksum = 0;
    header.identifier = @byteSwap(identifier);
    header.sequence = @byteSwap(sequence);

    const max_data_len = request_buf.len - @sizeOf(ICMPHeader);
    const data_len = if (data.len > max_data_len) max_data_len else data.len;
    if (data_len > 0) {
        @memcpy(request_buf[@sizeOf(ICMPHeader) .. @sizeOf(ICMPHeader) + data_len], data[0..data_len]);
    }

    const total_len = @sizeOf(ICMPHeader) + data_len;
    header.checksum = calculateChecksum(request_buf[0..total_len]);

    try ipv4.sendPacket(dst_ip, .ICMP, request_buf[0..total_len]);
}

fn calculateChecksum(data: []u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    while (i < data.len - 1) : (i += 2) {
        sum += (@as(u16, data[i]) << 8) | data[i + 1];
    }

    if (data.len % 2 == 1) {
        sum += @as(u16, data[data.len - 1]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @as(u16, @intCast(~sum));
}

fn verifyChecksum(data: []u8) bool {
    var sum: u32 = 0;
    var i: usize = 0;

    while (i < data.len - 1) : (i += 2) {
        sum += (@as(u16, data[i]) << 8) | data[i + 1];
    }

    if (data.len % 2 == 1) {
        sum += @as(u16, data[data.len - 1]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum == 0xFFFF;
}

