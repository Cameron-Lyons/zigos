// zlint-disable suppressed-errors
const ipv4 = @import("ipv4.zig");
const ipv6 = @import("ipv6.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");
const timer = @import("../timer/timer.zig");

const TCP_PROTOCOL = 6;
const TCP_MSS: u16 = 536;

const TCP_OPT_END: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;
const TCP_OPT_WINDOW_SCALE: u8 = 3;
const TCP_OPT_SACK_PERMITTED: u8 = 4;
const TCP_OPT_SACK: u8 = 5;
const TCP_OPT_TIMESTAMPS: u8 = 8;

const SACKBlock = struct {
    left_edge: u32,
    right_edge: u32,
};
const TCP_INITIAL_CWND: u32 = TCP_MSS * 2;
const TCP_INITIAL_SSTHRESH: u32 = 65535;
const TCP_INITIAL_RTO: u32 = 100;
const TCP_MAX_RTO: u32 = 6000;
const TCP_MIN_RTO: u32 = 20;
const TCP_MAX_RETRIES: u8 = 10;
const TCP_TIME_WAIT_TICKS: u64 = 12000;
const TCP_MAX_RETX_ENTRIES = 8;

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

const RetxEntry = struct {
    seq_num: u32,
    data_len: u16,
    send_time: u64,
    retries: u8,
    flags: u8,
    data: [TCP_MSS]u8,
    active: bool,
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
    send_una: u32,
    send_window: u16,
    recv_window: u16,
    recv_buffer: []u8,
    recv_buffer_used: usize,
    send_buffer: []u8,
    send_buffer_used: usize,
    cwnd: u32,
    ssthresh: u32,
    mss: u16,
    bytes_in_flight: u32,
    rto: u32,
    srtt: u32,
    rttvar: u32,
    dup_ack_count: u8,
    retx_count: u8,
    time_wait_start: u64,
    retx_queue: [TCP_MAX_RETX_ENTRIES]RetxEntry,
    window_scale_send: u8,
    window_scale_recv: u8,
    sack_permitted: bool,
    sack_blocks: [4]SACKBlock,
    ts_enabled: bool,
    ts_val: u32,
    ts_ecr: u32,
    ts_recent: u32,
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

    const header_bytes_ptr: [*]const u8 = @ptrCast(tcp_header);
    const header_bytes = header_bytes_ptr[0..@sizeOf(TCPHeader)];
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

pub fn calculateChecksumIPv6(src: *const ipv6.IPv6Address, dst: *const ipv6.IPv6Address, tcp_header: *const TCPHeader, data: []const u8) u16 {
    var sum: u32 = ipv6.calculatePseudoHeaderChecksum(src, dst, TCP_PROTOCOL, @intCast(@sizeOf(TCPHeader) + data.len));

    const header_bytes_ptr: [*]const u8 = @ptrCast(tcp_header);
    const header_bytes = header_bytes_ptr[0..@sizeOf(TCPHeader)];
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

fn sendTCPPacket(connection: *TCPConnectionStruct, flags: u8, data: []const u8) !void {
    const effective_window = @min(connection.recv_window, @as(u16, @intCast(@min(connection.cwnd, 0xFFFF))));
    if (data.len > 0 and connection.bytes_in_flight >= effective_window) {
        return error.WindowFull;
    }

    const is_syn = (flags & TCPFlags.SYN) != 0;
    // SAFETY: filled by buildOptions when is_syn or ts_enabled
    var options_buf: [40]u8 = undefined;
    const options_len = if (is_syn or connection.ts_enabled)
        buildOptions(connection, &options_buf, is_syn)
    else
        0;

    const header_len = @sizeOf(TCPHeader) + options_len;
    const packet_size = header_len + data.len;
    const packet_mem = memory.kmalloc(packet_size) orelse return error.OutOfMemory;
    defer memory.kfree(packet_mem);

    const packet: [*]u8 = @ptrCast(@alignCast(packet_mem));
    const tcp_header: *TCPHeader = @ptrCast(@alignCast(packet));

    tcp_header.src_port = @byteSwap(connection.local_port);
    tcp_header.dst_port = @byteSwap(connection.remote_port);
    tcp_header.seq_num = @byteSwap(connection.send_seq);
    tcp_header.ack_num = @byteSwap(connection.send_ack);
    tcp_header.setDataOffsetAndFlags(@intCast(header_len), flags);
    const scaled_window: u16 = if (connection.window_scale_send > 0)
        @intCast(@min(@as(u32, connection.send_window) >> @as(u5, @intCast(connection.window_scale_send)), 0xFFFF))
    else
        connection.send_window;
    tcp_header.window_size = @byteSwap(scaled_window);
    tcp_header.checksum = 0;
    tcp_header.urgent_ptr = 0;

    if (options_len > 0) {
        @memcpy(packet[@sizeOf(TCPHeader) .. @sizeOf(TCPHeader) + options_len], options_buf[0..options_len]);
    }

    if (data.len > 0) {
        @memcpy(packet[header_len..packet_size], data);
    }

    const payload_with_options = packet[@sizeOf(TCPHeader)..packet_size];
    tcp_header.checksum = calculateChecksum(connection.local_addr, connection.remote_addr, tcp_header, payload_with_options);

    try ipv4.sendPacket(connection.remote_addr, @enumFromInt(TCP_PROTOCOL), packet[0..packet_size]);

    if (data.len > 0 or (flags & (TCPFlags.SYN | TCPFlags.FIN)) != 0) {
        for (&connection.retx_queue) |*entry| {
            if (!entry.active) {
                entry.seq_num = connection.send_seq;
                entry.data_len = @intCast(data.len);
                entry.send_time = timer.getTicks();
                entry.retries = 0;
                entry.flags = flags;
                entry.active = true;
                if (data.len > 0) {
                    const copy_len = @min(data.len, TCP_MSS);
                    @memcpy(entry.data[0..copy_len], data[0..copy_len]);
                }
                break;
            }
        }
    }

    if (flags & TCPFlags.SYN != 0) {
        connection.send_seq +%= 1;
        connection.bytes_in_flight += 1;
    }
    if (flags & TCPFlags.FIN != 0) {
        connection.send_seq +%= 1;
        connection.bytes_in_flight += 1;
    }
    if (data.len > 0) {
        connection.send_seq +%= @intCast(data.len);
        connection.bytes_in_flight += @intCast(data.len);
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

            const initial_seq: u32 = @intCast(@mod(@as(u64, @intFromPtr(&maybe_conn)), 0x100000000));
            maybe_conn.* = TCPConnection{
                .local_addr = local_addr,
                .remote_addr = remote_addr,
                .local_port = local_port,
                .remote_port = remote_port,
                .state = .CLOSED,
                .send_seq = initial_seq,
                .recv_seq = 0,
                .send_ack = 0,
                .recv_ack = 0,
                .send_una = initial_seq,
                .send_window = TCP_BUFFER_SIZE,
                .recv_window = TCP_BUFFER_SIZE,
                .recv_buffer = blk: {
                    const ptr: [*]u8 = @ptrCast(@alignCast(recv_buf));
                    break :blk ptr[0..TCP_BUFFER_SIZE];
                },
                .recv_buffer_used = 0,
                .send_buffer = blk: {
                    const ptr: [*]u8 = @ptrCast(@alignCast(send_buf));
                    break :blk ptr[0..TCP_BUFFER_SIZE];
                },
                .send_buffer_used = 0,
                .cwnd = TCP_INITIAL_CWND,
                .ssthresh = TCP_INITIAL_SSTHRESH,
                .mss = TCP_MSS,
                .bytes_in_flight = 0,
                .rto = TCP_INITIAL_RTO,
                .srtt = 0,
                .rttvar = 0,
                .dup_ack_count = 0,
                .retx_count = 0,
                .time_wait_start = 0,
                .retx_queue = [_]RetxEntry{RetxEntry{
                    .seq_num = 0,
                    .data_len = 0,
                    .send_time = 0,
                    .retries = 0,
                    .flags = 0,
                    .data = [_]u8{0} ** TCP_MSS,
                    .active = false,
                }} ** TCP_MAX_RETX_ENTRIES,
                .window_scale_send = 0,
                .window_scale_recv = 0,
                .sack_permitted = false,
                .sack_blocks = [_]SACKBlock{SACKBlock{ .left_edge = 0, .right_edge = 0 }} ** 4,
                .ts_enabled = false,
                .ts_val = 0,
                .ts_ecr = 0,
                .ts_recent = 0,
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

    const tcp_header: *const TCPHeader = @ptrCast(@alignCast(data.ptr));
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
        if (header_len > @sizeOf(TCPHeader)) {
            const opt_start = @sizeOf(TCPHeader);
            const opt_end = @min(header_len, data.len);
            if (opt_end > opt_start) {
                parseOptions(data[opt_start..opt_end], conn);
            }
        }
        handleEstablishedConnection(conn, seq_num, ack_num, flags, window_size, payload);
    } else if (flags & TCPFlags.SYN != 0) {
        if (findListeningSocket(dst_port)) |_| {
            handleIncomingSYN(src_ip, dst_ip, src_port, dst_port, seq_num);
        } else {
            sendRST(src_ip, dst_ip, src_port, dst_port, ack_num);
        }
    }
}

fn processAck(conn: *TCPConnection, ack_num: u32) void {
    applySACKBlocks(conn);

    if (ack_num == conn.send_una) {
        conn.dup_ack_count += 1;
        if (conn.dup_ack_count == 3) {
            conn.ssthresh = @max(conn.bytes_in_flight / 2, @as(u32, conn.mss) * 2);
            conn.cwnd = conn.ssthresh + @as(u32, conn.mss) * 3;
            retransmitFirst(conn);
        }
        return;
    }

    const bytes_acked = ack_num -% conn.send_una;
    if (bytes_acked > 0 and seqLessThanEq(conn.send_una, ack_num)) {
        conn.bytes_in_flight -|= bytes_acked;
        conn.send_una = ack_num;
        conn.dup_ack_count = 0;
        conn.retx_count = 0;

        for (&conn.retx_queue) |*entry| {
            if (entry.active and seqLessThanEq(entry.seq_num +% entry.data_len, ack_num)) {
                const rtt = timer.getTicks() - entry.send_time;
                if (rtt > 0) updateRTT(conn, @intCast(rtt));
                entry.active = false;
            }
        }

        if (conn.cwnd < conn.ssthresh) {
            conn.cwnd += conn.mss;
        } else {
            conn.cwnd += @max(1, (@as(u32, conn.mss) * @as(u32, conn.mss)) / conn.cwnd);
        }
    }
}

fn updateRTT(conn: *TCPConnection, rtt: u32) void {
    if (conn.srtt == 0) {
        conn.srtt = rtt * 8;
        conn.rttvar = rtt * 4 / 2;
    } else {
        const diff = if (rtt * 8 > conn.srtt) rtt * 8 - conn.srtt else conn.srtt - rtt * 8;
        conn.rttvar = conn.rttvar - conn.rttvar / 4 + diff / 4;
        conn.srtt = conn.srtt - conn.srtt / 8 + rtt;
    }
    conn.rto = @min(TCP_MAX_RTO, @max(TCP_MIN_RTO, conn.srtt / 8 + conn.rttvar));
}

fn seqLessThan(a: u32, b: u32) bool {
    const diff: i32 = @bitCast(a -% b);
    return diff < 0;
}

fn seqLessThanEq(a: u32, b: u32) bool {
    return a == b or seqLessThan(a, b);
}

fn retransmitFirst(conn: *TCPConnection) void {
    for (&conn.retx_queue) |*entry| {
        if (entry.active) {
            const save_seq = conn.send_seq;
            conn.send_seq = entry.seq_num;
            sendTCPPacket(conn, entry.flags, entry.data[0..entry.data_len]) catch {};
            conn.send_seq = save_seq;
            entry.send_time = timer.getTicks();
            entry.retries += 1;
            break;
        }
    }
}

fn handleEstablishedConnection(conn: *TCPConnection, seq_num: u32, ack_num: u32, flags: u8, window_size: u16, payload: []const u8) void {
    conn.recv_window = if (conn.window_scale_recv > 0) @intCast(@min(@as(u32, window_size) << @as(u5, @intCast(conn.window_scale_recv)), 0xFFFF)) else window_size;

    if (flags & TCPFlags.RST != 0) {
        conn.state = .CLOSED;
        return;
    }

    switch (conn.state) {
        .SYN_SENT => {
            if (flags & TCPFlags.SYN != 0 and flags & TCPFlags.ACK != 0) {
                conn.recv_seq = seq_num +% 1;
                conn.send_ack = conn.recv_seq;
                conn.recv_ack = ack_num;
                conn.send_una = ack_num;
                conn.bytes_in_flight = 0;
                conn.state = .ESTABLISHED;
                clearRetxQueue(conn);
                sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
                vga.print("TCP: Connection established\n");
            }
        },
        .SYN_RECEIVED => {
            if (flags & TCPFlags.ACK != 0) {
                conn.send_una = ack_num;
                conn.bytes_in_flight = 0;
                conn.state = .ESTABLISHED;
                clearRetxQueue(conn);
                vga.print("TCP: Connection accepted\n");
            }
        },
        .ESTABLISHED => {
            if (flags & TCPFlags.ACK != 0) {
                processAck(conn, ack_num);
            }
            if (payload.len > 0 and seq_num == conn.recv_seq) {
                const space_available = conn.recv_buffer.len - conn.recv_buffer_used;
                const to_copy = @min(payload.len, space_available);
                if (to_copy > 0) {
                    @memcpy(conn.recv_buffer[conn.recv_buffer_used .. conn.recv_buffer_used + to_copy], payload[0..to_copy]);
                    conn.recv_buffer_used += to_copy;
                    conn.recv_seq +%= @intCast(to_copy);
                    conn.send_ack = conn.recv_seq;
                }
                sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
            }
            if (flags & TCPFlags.FIN != 0) {
                conn.recv_seq = seq_num +% @as(u32, @intCast(payload.len)) +% 1;
                conn.send_ack = conn.recv_seq;
                conn.state = .CLOSE_WAIT;
                sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
            }
        },
        .FIN_WAIT_1 => {
            if (flags & TCPFlags.ACK != 0) {
                processAck(conn, ack_num);
                if (flags & TCPFlags.FIN != 0) {
                    conn.recv_seq = seq_num +% 1;
                    conn.send_ack = conn.recv_seq;
                    conn.state = .TIME_WAIT;
                    conn.time_wait_start = timer.getTicks();
                    sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
                } else if (seqLessThanEq(conn.send_seq, ack_num)) {
                    conn.state = .FIN_WAIT_2;
                    clearRetxQueue(conn);
                }
            }
        },
        .FIN_WAIT_2 => {
            if (flags & TCPFlags.FIN != 0) {
                conn.recv_seq = seq_num +% 1;
                conn.send_ack = conn.recv_seq;
                conn.state = .TIME_WAIT;
                conn.time_wait_start = timer.getTicks();
                sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
            }
        },
        .CLOSING => {
            if (flags & TCPFlags.ACK != 0) {
                conn.state = .TIME_WAIT;
                conn.time_wait_start = timer.getTicks();
            }
        },
        .LAST_ACK => {
            if (flags & TCPFlags.ACK != 0) {
                conn.state = .CLOSED;
                clearRetxQueue(conn);
            }
        },
        .TIME_WAIT => {},
        .CLOSE_WAIT => {
            if (flags & TCPFlags.ACK != 0) {
                processAck(conn, ack_num);
            }
        },
        else => {},
    }
}

fn clearRetxQueue(conn: *TCPConnection) void {
    for (&conn.retx_queue) |*entry| {
        entry.active = false;
    }
    conn.bytes_in_flight = 0;
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

    const packet: [*]u8 = @ptrCast(@alignCast(packet_mem));
    const tcp_header: *TCPHeader = @ptrCast(@alignCast(packet));

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
    const socket = &(tcp_sockets[socket_id] orelse return error.InvalidSocket);

    const local_addr = ipv4.getLocalIP();
    const local_port: u16 = @intCast(49152 + (socket_id & 0x3FFF));

    const conn = try createConnection(local_addr, remote_addr, local_port, remote_port);
    socket.connection = conn;
    conn.state = .SYN_SENT;

    try sendTCPPacket(conn, TCPFlags.SYN, &[_]u8{});
}

pub fn send(socket_id: usize, data: []const u8) !usize {
    if (socket_id >= tcp_sockets.len) return error.InvalidSocket;
    const socket = &(tcp_sockets[socket_id] orelse return error.InvalidSocket);
    const conn = &(socket.connection orelse return error.NotConnected);

    if (conn.state != .ESTABLISHED) return error.NotConnected;

    const space_available = conn.send_buffer.len - conn.send_buffer_used;
    const to_send = @min(data.len, space_available);

    if (to_send == 0) return error.BufferFull;

    try sendTCPPacket(conn, TCPFlags.PSH | TCPFlags.ACK, data[0..to_send]);
    return to_send;
}

pub fn receive(socket_id: usize, buffer: []u8) !usize {
    if (socket_id >= tcp_sockets.len) return error.InvalidSocket;
    const socket = &(tcp_sockets[socket_id] orelse return error.InvalidSocket);
    const conn = &(socket.connection orelse return error.NotConnected);

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
    var socket = &(tcp_sockets[socket_id] orelse return error.InvalidSocket);

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

    const effective_window = @min(@as(u32, conn.recv_window), conn.cwnd);
    const available_window = if (effective_window > conn.bytes_in_flight) effective_window - conn.bytes_in_flight else 0;
    const max_send = @min(available_window, @as(u32, conn.mss));

    const space_available = conn.send_buffer.len - conn.send_buffer_used;
    const to_copy = @min(@min(data.len, space_available), max_send);

    if (to_copy == 0) {
        return error.NoBufferSpace;
    }

    @memcpy(conn.send_buffer[conn.send_buffer_used .. conn.send_buffer_used + to_copy], data[0..to_copy]);
    conn.send_buffer_used += to_copy;

    sendTCPPacket(conn, TCPFlags.PSH | TCPFlags.ACK, conn.send_buffer[0..conn.send_buffer_used]) catch |err| switch (err) {
        error.WindowFull => return error.NoBufferSpace,
        else => return err,
    };
    conn.send_buffer_used = 0;

    return to_copy;
}

pub fn closeConnection(conn: *TCPConnection) void {
    switch (conn.state) {
        .ESTABLISHED => {
            conn.state = .FIN_WAIT_1;
            sendTCPPacket(conn, TCPFlags.FIN | TCPFlags.ACK, &[_]u8{}) catch {};
        },
        .CLOSE_WAIT => {
            conn.state = .LAST_ACK;
            sendTCPPacket(conn, TCPFlags.FIN | TCPFlags.ACK, &[_]u8{}) catch {};
        },
        else => {},
    }
}

pub fn tick() void {
    const now = timer.getTicks();

    for (&tcp_connections) |*maybe_conn| {
        if (maybe_conn.*) |*conn| {
            if (conn.state == .TIME_WAIT) {
                if (now - conn.time_wait_start >= TCP_TIME_WAIT_TICKS) {
                    conn.state = .CLOSED;
                    clearRetxQueue(conn);
                }
                continue;
            }

            if (conn.state == .CLOSED) continue;

            for (&conn.retx_queue) |*entry| {
                if (entry.active and now - entry.send_time >= conn.rto) {
                    if (entry.retries >= TCP_MAX_RETRIES) {
                        conn.state = .CLOSED;
                        clearRetxQueue(conn);
                        vga.print("TCP: Connection timed out\n");
                        break;
                    }

                    conn.ssthresh = @max(conn.bytes_in_flight / 2, @as(u32, conn.mss) * 2);
                    conn.cwnd = conn.mss;

                    const save_seq = conn.send_seq;
                    conn.send_seq = entry.seq_num;
                    sendTCPPacket(conn, entry.flags, entry.data[0..entry.data_len]) catch {};
                    conn.send_seq = save_seq;

                    entry.send_time = now;
                    entry.retries += 1;
                    conn.rto = @min(TCP_MAX_RTO, conn.rto * 2);
                    conn.retx_count += 1;
                }
            }
        }
    }
}

fn parseOptions(data: []const u8, conn: *TCPConnectionStruct) void {
    var i: usize = 0;
    while (i < data.len) {
        const kind = data[i];
        if (kind == TCP_OPT_END) break;
        if (kind == TCP_OPT_NOP) {
            i += 1;
            continue;
        }

        if (i + 1 >= data.len) break;
        const opt_len = data[i + 1];
        if (opt_len < 2 or i + opt_len > data.len) break;

        switch (kind) {
            TCP_OPT_MSS => {
                if (opt_len == 4 and i + 3 < data.len) {
                    conn.mss = @as(u16, data[i + 2]) << 8 | data[i + 3];
                }
            },
            TCP_OPT_WINDOW_SCALE => {
                if (opt_len == 3 and i + 2 < data.len) {
                    conn.window_scale_recv = data[i + 2];
                    if (conn.window_scale_recv > 14) conn.window_scale_recv = 14;
                }
            },
            TCP_OPT_SACK_PERMITTED => {
                if (opt_len == 2) {
                    conn.sack_permitted = true;
                }
            },
            TCP_OPT_SACK => {
                const num_blocks = (opt_len - 2) / 8;
                var b: usize = 0;
                while (b < num_blocks and b < 4) : (b += 1) {
                    const base = i + 2 + b * 8;
                    if (base + 7 < data.len) {
                        conn.sack_blocks[b] = SACKBlock{
                            .left_edge = @as(u32, data[base]) << 24 | @as(u32, data[base + 1]) << 16 | @as(u32, data[base + 2]) << 8 | data[base + 3],
                            .right_edge = @as(u32, data[base + 4]) << 24 | @as(u32, data[base + 5]) << 16 | @as(u32, data[base + 6]) << 8 | data[base + 7],
                        };
                    }
                }
            },
            TCP_OPT_TIMESTAMPS => {
                if (opt_len == 10 and i + 9 < data.len) {
                    const tsval = @as(u32, data[i + 2]) << 24 | @as(u32, data[i + 3]) << 16 | @as(u32, data[i + 4]) << 8 | data[i + 5];
                    const tsecr = @as(u32, data[i + 6]) << 24 | @as(u32, data[i + 7]) << 16 | @as(u32, data[i + 8]) << 8 | data[i + 9];
                    conn.ts_enabled = true;
                    updateTimestampValues(conn, tsval, tsecr);
                }
            },
            else => {},
        }

        i += opt_len;
    }
}

fn buildOptions(conn: *TCPConnectionStruct, buf: []u8, is_syn: bool) usize {
    var offset: usize = 0;

    if (is_syn) {
        if (offset + 4 <= buf.len) {
            buf[offset] = TCP_OPT_MSS;
            buf[offset + 1] = 4;
            buf[offset + 2] = @intCast((conn.mss >> 8) & 0xFF);
            buf[offset + 3] = @intCast(conn.mss & 0xFF);
            offset += 4;
        }

        if (offset + 3 <= buf.len) {
            buf[offset] = TCP_OPT_WINDOW_SCALE;
            buf[offset + 1] = 3;
            buf[offset + 2] = conn.window_scale_send;
            offset += 3;
        }

        if (offset + 2 <= buf.len) {
            buf[offset] = TCP_OPT_SACK_PERMITTED;
            buf[offset + 1] = 2;
            offset += 2;
        }

        if (offset + 1 <= buf.len) {
            buf[offset] = TCP_OPT_NOP;
            offset += 1;
        }
    }

    if (conn.ts_enabled) {
        while (offset % 4 != 0 and offset < buf.len) {
            buf[offset] = TCP_OPT_NOP;
            offset += 1;
        }

        if (offset + 10 <= buf.len) {
            buf[offset] = TCP_OPT_TIMESTAMPS;
            buf[offset + 1] = 10;
            const ts = conn.ts_val;
            buf[offset + 2] = @intCast((ts >> 24) & 0xFF);
            buf[offset + 3] = @intCast((ts >> 16) & 0xFF);
            buf[offset + 4] = @intCast((ts >> 8) & 0xFF);
            buf[offset + 5] = @intCast(ts & 0xFF);
            const ecr = conn.ts_ecr;
            buf[offset + 6] = @intCast((ecr >> 24) & 0xFF);
            buf[offset + 7] = @intCast((ecr >> 16) & 0xFF);
            buf[offset + 8] = @intCast((ecr >> 8) & 0xFF);
            buf[offset + 9] = @intCast(ecr & 0xFF);
            offset += 10;
        }
    }

    while (offset % 4 != 0 and offset < buf.len) {
        buf[offset] = TCP_OPT_NOP;
        offset += 1;
    }

    return offset;
}

fn applySACKBlocks(conn: *TCPConnectionStruct) void {
    if (!conn.sack_permitted) return;

    for (&conn.sack_blocks) |*block| {
        if (block.left_edge == 0 and block.right_edge == 0) continue;

        for (&conn.retx_queue) |*entry| {
            if (entry.active) {
                const entry_end = entry.seq_num +% entry.data_len;
                if (seqLessThanEq(block.left_edge, entry.seq_num) and
                    seqLessThanEq(entry_end, block.right_edge))
                {
                    entry.active = false;
                    conn.bytes_in_flight -|= entry.data_len;
                }
            }
        }

        block.left_edge = 0;
        block.right_edge = 0;
    }
}

fn updateTimestampValues(conn: *TCPConnectionStruct, tsval: u32, tsecr: u32) void {
    conn.ts_recent = tsval;
    conn.ts_ecr = tsval;

    if (tsecr != 0 and conn.ts_enabled) {
        const now: u32 = @intCast(timer.getTicks() & 0xFFFFFFFF);
        const rtt = now -% tsecr;
        if (rtt > 0 and rtt < 60000) {
            updateRTT(conn, rtt);
        }
    }

    conn.ts_val = @intCast(timer.getTicks() & 0xFFFFFFFF);
}

pub fn registerListeningSocket(sock: *@import("socket.zig").Socket) void {
    for (&tcp_sockets) |*maybe_socket| {
        if (maybe_socket.* == null) {
            maybe_socket.* = TCPSocket{
                .connection = null,
                .listening = true,
                .port = sock.local_port,
            };
            return;
        }
    }
}