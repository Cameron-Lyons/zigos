const std = @import("std");
const network = @import("network.zig");
const ipv4 = @import("ipv4.zig");
const memory = @import("memory.zig");
const vga = @import("vga.zig");

const TCP_PROTOCOL = 6;

const TCPFlags = struct {
    const FIN = 1 << 0;
    const SYN = 1 << 1;
    const RST = 1 << 2;
    const PSH = 1 << 3;
    const ACK = 1 << 4;
    const URG = 1 << 5;
};

const TCPState = enum {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
};

const TCPHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset_and_flags: u16,
    window_size: u16,
    checksum: u16,
    urgent_ptr: u16,

    pub fn getDataOffset(self: *const TCPHeader) u8 {
        return @intCast((@byteSwap(self.data_offset_and_flags) >> 12) * 4);
    }

    pub fn getFlags(self: *const TCPHeader) u8 {
        return @intCast(@byteSwap(self.data_offset_and_flags) & 0x3F);
    }

    pub fn setDataOffsetAndFlags(self: *TCPHeader, data_offset: u8, flags: u8) void {
        const offset_in_words = data_offset / 4;
        self.data_offset_and_flags = @byteSwap(@as(u16, offset_in_words) << 12 | @as(u16, flags));
    }
};

const TCPConnectionStruct = struct {
    local_addr: u32,
    remote_addr: u32,
    local_port: u16,
    remote_port: u16,
    state: TCPState,
    send_seq: u32,
    recv_seq: u32,
    send_ack: u32,
    recv_ack: u32,
    send_window: u16,
    recv_window: u16,
    recv_buffer: []u8,
    recv_buffer_used: usize,
    send_buffer: []u8,
    send_buffer_used: usize,
};

const TCPSocket = struct {
    connection: ?TCPConnectionStruct,
    listening: bool,
    port: u16,
};

const MAX_TCP_CONNECTIONS = 32;
const TCP_BUFFER_SIZE = 4096;

var tcp_connections: [MAX_TCP_CONNECTIONS]?TCPConnectionStruct = [_]?TCPConnectionStruct{null} ** MAX_TCP_CONNECTIONS;
var tcp_sockets: [MAX_TCP_CONNECTIONS]?TCPSocket = [_]?TCPSocket{null} ** MAX_TCP_CONNECTIONS;

pub fn init() void {
    ipv4.registerProtocolHandler(TCP_PROTOCOL, handleTCPPacket);
}

fn calculateChecksum(src_ip: u32, dst_ip: u32, tcp_header: *const TCPHeader, data: []const u8) u16 {
    var sum: u32 = 0;

    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;

    sum += TCP_PROTOCOL;
    sum += @sizeOf(TCPHeader) + data.len;

    const header_bytes = @as([*]const u8, @ptrCast(tcp_header))[0..@sizeOf(TCPHeader)];
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

    return ~@as(u16, @intCast(sum));
}

fn sendTCPPacket(connection: *TCPConnectionStruct, flags: u8, data: []const u8) !void {
    const packet_size = @sizeOf(TCPHeader) + data.len;
    const packet_mem = memory.kmalloc(packet_size) orelse return error.OutOfMemory;
    defer memory.kfree(packet_mem);

    const packet = @as([*]u8, @ptrCast(@alignCast(packet_mem)));
    const tcp_header = @as(*TCPHeader, @ptrCast(@alignCast(packet)));

    tcp_header.src_port = @byteSwap(connection.local_port);
    tcp_header.dst_port = @byteSwap(connection.remote_port);
    tcp_header.seq_num = @byteSwap(connection.send_seq);
    tcp_header.ack_num = @byteSwap(connection.send_ack);
    tcp_header.setDataOffsetAndFlags(@sizeOf(TCPHeader), flags);
    tcp_header.window_size = @byteSwap(connection.send_window);
    tcp_header.checksum = 0;
    tcp_header.urgent_ptr = 0;

    if (data.len > 0) {
        @memcpy(packet[@sizeOf(TCPHeader)..packet_size], data);
    }

    tcp_header.checksum = calculateChecksum(connection.local_addr, connection.remote_addr, tcp_header, data);

    try ipv4.sendPacket(connection.remote_addr, @enumFromInt(TCP_PROTOCOL), packet[0..packet_size]);

    if (flags & TCPFlags.SYN != 0) {
        connection.send_seq +%= 1;
    }
    if (data.len > 0) {
        connection.send_seq +%= @intCast(data.len);
    }
}

fn findConnection(local_addr: u32, remote_addr: u32, local_port: u16, remote_port: u16) ?*TCPConnection {
    for (&tcp_connections) |*maybe_conn| {
        if (maybe_conn.*) |*conn| {
            if (conn.local_addr == local_addr and
                conn.remote_addr == remote_addr and
                conn.local_port == local_port and
                conn.remote_port == remote_port)
            {
                return conn;
            }
        }
    }
    return null;
}

fn findListeningSocket(port: u16) ?*TCPSocket {
    for (&tcp_sockets) |*maybe_socket| {
        if (maybe_socket.*) |*socket| {
            if (socket.listening and socket.port == port) {
                return socket;
            }
        }
    }
    return null;
}

pub const TCPConnection = TCPConnectionStruct;

pub fn createConnection(local_addr: ipv4.IPv4Address, local_port: u16, remote_addr: ipv4.IPv4Address, remote_port: u16) !*TCPConnection {
    const local_addr_u32 = (@as(u32, local_addr.octets[0]) << 24) | 
                           (@as(u32, local_addr.octets[1]) << 16) | 
                           (@as(u32, local_addr.octets[2]) << 8) | 
                           local_addr.octets[3];
    const remote_addr_u32 = (@as(u32, remote_addr.octets[0]) << 24) | 
                            (@as(u32, remote_addr.octets[1]) << 16) | 
                            (@as(u32, remote_addr.octets[2]) << 8) | 
                            remote_addr.octets[3];
    return createConnectionInternal(local_addr_u32, remote_addr_u32, local_port, remote_port);
}

fn createConnectionInternal(local_addr: u32, remote_addr: u32, local_port: u16, remote_port: u16) !*TCPConnection {
    for (&tcp_connections) |*maybe_conn| {
        if (maybe_conn.* == null) {
            const recv_buf = memory.kmalloc(TCP_BUFFER_SIZE) orelse return error.OutOfMemory;
            const send_buf = memory.kmalloc(TCP_BUFFER_SIZE) orelse {
                memory.kfree(recv_buf);
                return error.OutOfMemory;
            };

            maybe_conn.* = TCPConnection{
                .local_addr = local_addr,
                .remote_addr = remote_addr,
                .local_port = local_port,
                .remote_port = remote_port,
                .state = .CLOSED,
                .send_seq = @intCast(@mod(@as(u64, @intFromPtr(&maybe_conn)), 0x100000000)),
                .recv_seq = 0,
                .send_ack = 0,
                .recv_ack = 0,
                .send_window = TCP_BUFFER_SIZE,
                .recv_window = TCP_BUFFER_SIZE,
                .recv_buffer = @as([*]u8, @ptrCast(@alignCast(recv_buf)))[0..TCP_BUFFER_SIZE],
                .recv_buffer_used = 0,
                .send_buffer = @as([*]u8, @ptrCast(@alignCast(send_buf)))[0..TCP_BUFFER_SIZE],
                .send_buffer_used = 0,
            };
            return &maybe_conn.*.?;
        }
    }
    return error.NoConnectionSlots;
}

fn handleTCPPacket(src_ip: u32, dst_ip: u32, data: []const u8) void {
    if (data.len < @sizeOf(TCPHeader)) {
        return;
    }

    const tcp_header = @as(*const TCPHeader, @ptrCast(@alignCast(data.ptr)));
    const header_len = tcp_header.getDataOffset();
    if (header_len < @sizeOf(TCPHeader) or header_len > data.len) {
        return;
    }

    const checksum = tcp_header.checksum;
    var temp_header = tcp_header.*;
    temp_header.checksum = 0;
    const calculated_checksum = calculateChecksum(src_ip, dst_ip, &temp_header, data[header_len..]);
    if (checksum != calculated_checksum) {
        vga.print("TCP: Invalid checksum\n");
        return;
    }

    const src_port = @byteSwap(tcp_header.src_port);
    const dst_port = @byteSwap(tcp_header.dst_port);
    const seq_num = @byteSwap(tcp_header.seq_num);
    const ack_num = @byteSwap(tcp_header.ack_num);
    const flags = tcp_header.getFlags();
    const window_size = @byteSwap(tcp_header.window_size);
    const payload = data[header_len..];

    if (findConnection(dst_ip, src_ip, dst_port, src_port)) |conn| {
        handleEstablishedConnection(conn, seq_num, ack_num, flags, window_size, payload);
    } else if (flags & TCPFlags.SYN != 0) {
        if (findListeningSocket(dst_port)) |_| {
            handleIncomingSYN(src_ip, dst_ip, src_port, dst_port, seq_num);
        } else {
            sendRST(src_ip, dst_ip, src_port, dst_port, ack_num);
        }
    }
}

fn handleEstablishedConnection(conn: *TCPConnection, seq_num: u32, ack_num: u32, flags: u8, window_size: u16, payload: []const u8) void {
    conn.recv_window = window_size;

    switch (conn.state) {
        .SYN_SENT => {
            if (flags & TCPFlags.SYN != 0 and flags & TCPFlags.ACK != 0) {
                conn.recv_seq = seq_num +% 1;
                conn.send_ack = conn.recv_seq;
                conn.recv_ack = ack_num;
                conn.state = .ESTABLISHED;
                sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
                vga.print("TCP: Connection established\n");
            }
        },
        .SYN_RECEIVED => {
            if (flags & TCPFlags.ACK != 0) {
                conn.state = .ESTABLISHED;
                vga.print("TCP: Connection accepted\n");
            }
        },
        .ESTABLISHED => {
            if (flags & TCPFlags.FIN != 0) {
                conn.recv_seq = seq_num +% 1;
                conn.send_ack = conn.recv_seq;
                conn.state = .CLOSE_WAIT;
                sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
            } else if (payload.len > 0) {
                if (seq_num == conn.recv_seq) {
                    const space_available = conn.recv_buffer.len - conn.recv_buffer_used;
                    const to_copy = @min(payload.len, space_available);
                    if (to_copy > 0) {
                        @memcpy(conn.recv_buffer[conn.recv_buffer_used..conn.recv_buffer_used + to_copy], payload[0..to_copy]);
                        conn.recv_buffer_used += to_copy;
                        conn.recv_seq +%= @intCast(to_copy);
                        conn.send_ack = conn.recv_seq;
                    }
                    sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
                }
            }
            if (flags & TCPFlags.ACK != 0) {
                conn.recv_ack = ack_num;
            }
        },
        else => {},
    }
}

fn handleIncomingSYN(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, seq_num: u32) void {
    const local_addr = ipv4.IPv4Address.fromU32(dst_ip);
    const remote_addr = ipv4.IPv4Address.fromU32(src_ip);
    const conn = createConnection(local_addr, dst_port, remote_addr, src_port) catch {
        sendRST(src_ip, dst_ip, src_port, dst_port, seq_num +% 1);
        return;
    };

    conn.recv_seq = seq_num +% 1;
    conn.send_ack = conn.recv_seq;
    conn.state = .SYN_RECEIVED;

    sendTCPPacket(conn, TCPFlags.SYN | TCPFlags.ACK, &[_]u8{}) catch {
        conn.state = .CLOSED;
    };
}

fn sendRST(dst_ip: u32, src_ip: u32, dst_port: u16, src_port: u16, seq_num: u32) void {
    const packet_size = @sizeOf(TCPHeader);
    const packet_mem = memory.kmalloc(packet_size) orelse return;
    defer memory.kfree(packet_mem);

    const packet = @as([*]u8, @ptrCast(@alignCast(packet_mem)));
    const tcp_header = @as(*TCPHeader, @ptrCast(@alignCast(packet)));

    tcp_header.src_port = @byteSwap(src_port);
    tcp_header.dst_port = @byteSwap(dst_port);
    tcp_header.seq_num = @byteSwap(seq_num);
    tcp_header.ack_num = 0;
    tcp_header.setDataOffsetAndFlags(@sizeOf(TCPHeader), TCPFlags.RST);
    tcp_header.window_size = 0;
    tcp_header.checksum = 0;
    tcp_header.urgent_ptr = 0;

    tcp_header.checksum = calculateChecksum(src_ip, dst_ip, tcp_header, &[_]u8{});

    ipv4.sendPacket(dst_ip, @enumFromInt(TCP_PROTOCOL), packet[0..packet_size]) catch {};
}

pub fn listen(port: u16) !usize {
    for (&tcp_sockets, 0..) |*maybe_socket, i| {
        if (maybe_socket.* == null) {
            maybe_socket.* = TCPSocket{
                .connection = null,
                .listening = true,
                .port = port,
            };
            return i;
        }
    }
    return error.NoSocketSlots;
}

pub fn connect(socket_id: usize, remote_addr: u32, remote_port: u16) !void {
    if (socket_id >= tcp_sockets.len) return error.InvalidSocket;
    const socket = &tcp_sockets[socket_id] orelse return error.InvalidSocket;

    const local_addr = ipv4.getLocalIP();
    const local_port = @as(u16, @intCast(49152 + (socket_id & 0x3FFF)));

    const conn = try createConnection(local_addr, remote_addr, local_port, remote_port);
    socket.connection = conn;
    conn.state = .SYN_SENT;

    try sendTCPPacket(conn, TCPFlags.SYN, &[_]u8{});
}

pub fn send(socket_id: usize, data: []const u8) !usize {
    if (socket_id >= tcp_sockets.len) return error.InvalidSocket;
    const socket = &tcp_sockets[socket_id] orelse return error.InvalidSocket;
    const conn = &socket.connection orelse return error.NotConnected;

    if (conn.state != .ESTABLISHED) return error.NotConnected;

    const space_available = conn.send_buffer.len - conn.send_buffer_used;
    const to_send = @min(data.len, space_available);

    if (to_send == 0) return error.BufferFull;

    try sendTCPPacket(conn, TCPFlags.PSH | TCPFlags.ACK, data[0..to_send]);
    return to_send;
}

pub fn receive(socket_id: usize, buffer: []u8) !usize {
    if (socket_id >= tcp_sockets.len) return error.InvalidSocket;
    const socket = &tcp_sockets[socket_id] orelse return error.InvalidSocket;
    const conn = &socket.connection orelse return error.NotConnected;

    if (conn.recv_buffer_used == 0) return 0;

    const to_copy = @min(buffer.len, conn.recv_buffer_used);
    @memcpy(buffer[0..to_copy], conn.recv_buffer[0..to_copy]);

    if (to_copy < conn.recv_buffer_used) {
        const remaining = conn.recv_buffer_used - to_copy;
        @memcpy(conn.recv_buffer[0..remaining], conn.recv_buffer[to_copy..conn.recv_buffer_used]);
    }
    conn.recv_buffer_used -= to_copy;

    return to_copy;
}

pub fn close(socket_id: usize) !void {
    if (socket_id >= tcp_sockets.len) return error.InvalidSocket;
    const socket = &tcp_sockets[socket_id] orelse return error.InvalidSocket;

    if (socket.connection) |*conn| {
        if (conn.state == .ESTABLISHED) {
            conn.state = .FIN_WAIT_1;
            try sendTCPPacket(conn, TCPFlags.FIN | TCPFlags.ACK, &[_]u8{});
        }
        memory.kfree(conn.recv_buffer.ptr);
        memory.kfree(conn.send_buffer.ptr);
    }

    tcp_sockets[socket_id] = null;
}

pub fn initiateConnection(conn: *TCPConnection) !void {
    conn.state = .SYN_SENT;
    try sendTCPPacket(conn, TCPFlags.SYN, &[_]u8{});
}

pub fn sendData(conn: *TCPConnection, data: []const u8) !usize {
    if (conn.state != .ESTABLISHED) {
        return error.NotConnected;
    }
    
    const space_available = conn.send_buffer.len - conn.send_buffer_used;
    const to_copy = @min(data.len, space_available);
    
    if (to_copy == 0) {
        return error.NoBufferSpace;
    }
    
    @memcpy(conn.send_buffer[conn.send_buffer_used..conn.send_buffer_used + to_copy], data[0..to_copy]);
    conn.send_buffer_used += to_copy;
    
    try sendTCPPacket(conn, TCPFlags.PSH | TCPFlags.ACK, conn.send_buffer[0..conn.send_buffer_used]);
    conn.send_seq +%= @intCast(conn.send_buffer_used);
    conn.send_buffer_used = 0;
    
    return to_copy;
}

pub fn closeConnection(conn: *TCPConnection) void {
    if (conn.state == .ESTABLISHED) {
        conn.state = .FIN_WAIT_1;
        sendTCPPacket(conn, TCPFlags.FIN | TCPFlags.ACK, &[_]u8{}) catch {};
    }
}

pub fn registerListeningSocket(sock: *@import("socket.zig").Socket) void {
    _ = sock;
}