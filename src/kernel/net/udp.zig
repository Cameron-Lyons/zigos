const network = @import("network.zig");
const ipv4 = @import("ipv4.zig");
const ipv6 = @import("ipv6.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");

const UDP_PROTOCOL = 17;

const UDPHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

const UDPSocket = struct {
    port: u16,
    recv_buffer: []u8,
    recv_buffer_used: usize,
    recv_addr: u32,
    recv_port: u16,
};

const MAX_UDP_SOCKETS = 16;
const UDP_BUFFER_SIZE = 2048;

var udp_sockets: [MAX_UDP_SOCKETS]?UDPSocket = [_]?UDPSocket{null} ** MAX_UDP_SOCKETS;

pub fn init() void {
    ipv4.registerProtocolHandler(UDP_PROTOCOL, handleUDPPacket);
    ipv6.registerProtocolHandler(NEXT_HEADER_UDP, handleUDPPacketIPv6);
}

const NEXT_HEADER_UDP: u8 = 17;

fn handleUDPPacketIPv6(src: *const ipv6.IPv6Address, dst: *const ipv6.IPv6Address, data: []const u8) void {
    if (data.len < @sizeOf(UDPHeader)) return;

    const udp_header: *const UDPHeader = @ptrCast(@alignCast(data.ptr));
    const length = @byteSwap(udp_header.length);

    if (length < @sizeOf(UDPHeader) or length > data.len) return;

    if (udp_header.checksum != 0) {
        var temp_header = udp_header.*;
        temp_header.checksum = 0;
        const calculated = calculateChecksumIPv6(src, dst, &temp_header, data[@sizeOf(UDPHeader)..length]);
        if (udp_header.checksum != calculated) return;
    }

    const dst_port = @byteSwap(udp_header.dst_port);
    const payload = data[@sizeOf(UDPHeader)..length];

    if (findSocket(dst_port)) |socket| {
        const space_available = socket.recv_buffer.len - socket.recv_buffer_used;
        const to_copy = @min(payload.len, space_available);
        if (to_copy > 0) {
            @memcpy(socket.recv_buffer[socket.recv_buffer_used .. socket.recv_buffer_used + to_copy], payload[0..to_copy]);
            socket.recv_buffer_used = to_copy;
            socket.recv_addr = 0;
            socket.recv_port = @byteSwap(udp_header.src_port);
        }
    }
}

pub fn send(local_addr: ipv4.IPv4Address, local_port: u16, remote_addr: ipv4.IPv4Address, remote_port: u16, data: []const u8) !void {
    _ = local_addr;

    const packet_size = @sizeOf(UDPHeader) + data.len;
    const packet_mem = memory.kmalloc(packet_size) orelse return error.OutOfMemory;
    defer memory.kfree(packet_mem);

    const packet: [*]u8 = @ptrCast(@alignCast(packet_mem));
    const udp_header: *UDPHeader = @ptrCast(@alignCast(packet));

    udp_header.src_port = @byteSwap(local_port);
    udp_header.dst_port = @byteSwap(remote_port);
    udp_header.length = @byteSwap(@as(u16, @intCast(packet_size)));
    udp_header.checksum = 0;

    @memcpy(packet[@sizeOf(UDPHeader)..packet_size], data);

    const dst_ip = (@as(u32, remote_addr.octets[0]) << 24) |
                    (@as(u32, remote_addr.octets[1]) << 16) |
                    (@as(u32, remote_addr.octets[2]) << 8) |
                    remote_addr.octets[3];

    const src_ip_u32 = network.getLocalIPRaw();
    udp_header.checksum = calculateChecksum(src_ip_u32, dst_ip, udp_header, data);

    try ipv4.sendPacket(dst_ip, @enumFromInt(UDP_PROTOCOL), packet[0..packet_size]);
}

fn calculateChecksum(src_ip: u32, dst_ip: u32, udp_header: *const UDPHeader, data: []const u8) u16 {
    var sum: u32 = 0;

    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;

    sum += UDP_PROTOCOL;
    sum += @byteSwap(udp_header.length);

    const header_bytes_ptr: [*]const u8 = @ptrCast(udp_header);
    const header_bytes = header_bytes_ptr[0..@sizeOf(UDPHeader)];
    var i: usize = 0;
    while (i < header_bytes.len - 1) : (i += 2) {
        sum += @as(u16, header_bytes[i]) << 8 | header_bytes[i + 1];
    }

    i = 0;
    while (i < data.len - 1) : (i += 2) {
        sum += @as(u16, data[i]) << 8 | data[i + 1];
    }
    if (data.len & 1 != 0) {
        sum += @as(u16, data[data.len - 1]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const result: u16 = @intCast(sum);
    return ~result;
}

pub fn calculateChecksumIPv6(src: *const ipv6.IPv6Address, dst: *const ipv6.IPv6Address, udp_header: *const UDPHeader, data: []const u8) u16 {
    var sum: u32 = ipv6.calculatePseudoHeaderChecksum(src, dst, UDP_PROTOCOL, @byteSwap(udp_header.length));

    const header_bytes_ptr: [*]const u8 = @ptrCast(udp_header);
    const header_bytes = header_bytes_ptr[0..@sizeOf(UDPHeader)];
    var i: usize = 0;
    while (i < header_bytes.len - 1) : (i += 2) {
        sum += @as(u16, header_bytes[i]) << 8 | header_bytes[i + 1];
    }

    i = 0;
    while (i < data.len - 1) : (i += 2) {
        sum += @as(u16, data[i]) << 8 | data[i + 1];
    }
    if (data.len & 1 != 0) {
        sum += @as(u16, data[data.len - 1]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const result: u16 = @intCast(sum);
    return ~result;
}

fn findSocket(port: u16) ?*UDPSocket {
    for (&udp_sockets) |*maybe_socket| {
        if (maybe_socket.*) |*socket| {
            if (socket.port == port) {
                return socket;
            }
        }
    }
    return null;
}

fn handleUDPPacket(src_ip: u32, dst_ip: u32, data: []const u8) void {
    if (data.len < @sizeOf(UDPHeader)) {
        return;
    }

    const udp_header: *const UDPHeader = @ptrCast(@alignCast(data.ptr));
    const length = @byteSwap(udp_header.length);

    if (length < @sizeOf(UDPHeader) or length > data.len) {
        return;
    }

    if (udp_header.checksum != 0) {
        const checksum = udp_header.checksum;
        var temp_header = udp_header.*;
        temp_header.checksum = 0;
        const calculated_checksum = calculateChecksum(src_ip, dst_ip, &temp_header, data[@sizeOf(UDPHeader)..length]);
        if (checksum != calculated_checksum) {
            vga.print("UDP: Invalid checksum\n");
            return;
        }
    }

    const src_port = @byteSwap(udp_header.src_port);
    const dst_port = @byteSwap(udp_header.dst_port);
    const payload = data[@sizeOf(UDPHeader)..length];

    if (dst_port == 68) {
        const dhcp = @import("dhcp.zig");
        dhcp.handlePacket(payload);
    }

    if (findSocket(dst_port)) |socket| {
        const space_available = socket.recv_buffer.len - socket.recv_buffer_used;
        const to_copy = @min(payload.len, space_available);
        if (to_copy > 0) {
            @memcpy(socket.recv_buffer[socket.recv_buffer_used..socket.recv_buffer_used + to_copy], payload[0..to_copy]);
            socket.recv_buffer_used = to_copy;
            socket.recv_addr = src_ip;
            socket.recv_port = src_port;
        }
    }
}

pub fn bind(port: u16) !usize {
    for (&udp_sockets, 0..) |*maybe_socket, i| {
        if (maybe_socket.* == null) {
            const recv_buf = memory.kmalloc(UDP_BUFFER_SIZE) orelse return error.OutOfMemory;

            maybe_socket.* = UDPSocket{
                .port = port,
                .recv_buffer = blk: {
                    const ptr: [*]u8 = @ptrCast(@alignCast(recv_buf));
                    break :blk ptr[0..UDP_BUFFER_SIZE];
                },
                .recv_buffer_used = 0,
                .recv_addr = 0,
                .recv_port = 0,
            };
            return i;
        }
    }
    return error.NoSocketSlots;
}

pub fn sendTo(socket_id: usize, dst_ip: u32, dst_port: u16, data: []const u8) !void {
    if (socket_id >= udp_sockets.len) return error.InvalidSocket;
    const socket = &udp_sockets[socket_id] orelse return error.InvalidSocket;

    const packet_size = @sizeOf(UDPHeader) + data.len;
    const packet_mem = memory.kmalloc(packet_size) orelse return error.OutOfMemory;
    defer memory.kfree(packet_mem);

    const packet: [*]u8 = @ptrCast(@alignCast(packet_mem));
    const udp_header: *UDPHeader = @ptrCast(@alignCast(packet));

    udp_header.src_port = @byteSwap(socket.port);
    udp_header.dst_port = @byteSwap(dst_port);
    udp_header.length = @byteSwap(@as(u16, @intCast(packet_size)));
    udp_header.checksum = 0;

    @memcpy(packet[@sizeOf(UDPHeader)..packet_size], data);

    const local_ip = ipv4.getLocalIP();
    udp_header.checksum = calculateChecksum(local_ip, dst_ip, udp_header, data);

    try ipv4.sendPacket(dst_ip, @enumFromInt(UDP_PROTOCOL), packet[0..packet_size]);
}

pub fn receiveFrom(socket_id: usize, buffer: []u8, src_addr: *u32, src_port: *u16) !usize {
    if (socket_id >= udp_sockets.len) return error.InvalidSocket;
    const socket = &udp_sockets[socket_id] orelse return error.InvalidSocket;

    if (socket.recv_buffer_used == 0) return 0;

    const to_copy = @min(buffer.len, socket.recv_buffer_used);
    @memcpy(buffer[0..to_copy], socket.recv_buffer[0..to_copy]);

    src_addr.* = socket.recv_addr;
    src_port.* = socket.recv_port;

    socket.recv_buffer_used = 0;

    return to_copy;
}

pub fn close(socket_id: usize) !void {
    if (socket_id >= udp_sockets.len) return error.InvalidSocket;
    const socket = &udp_sockets[socket_id] orelse return error.InvalidSocket;

    memory.kfree(socket.recv_buffer.ptr);
    udp_sockets[socket_id] = null;
}