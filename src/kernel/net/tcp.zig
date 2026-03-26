const ipv4 = @import("ipv4.zig");
const ipv6 = @import("ipv6.zig");
const protocol = @import("tcp/protocol.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("../drivers/vga.zig");
const readiness = @import("../process/syscall/readiness.zig");
const timer = @import("../timer/timer.zig");
const sync = @import("../utils/sync.zig");

const TCP_PROTOCOL = protocol.PROTOCOL_NUMBER;
const TCP_MSS = protocol.MSS;
const SACKBlock = protocol.SACKBlock;
const TCP_INITIAL_CWND: u32 = TCP_MSS * 2;
const TCP_INITIAL_SSTHRESH: u32 = 65535;
const TCP_INITIAL_RTO: u32 = 100;
const TCP_MAX_RTO: u32 = 6000;
const TCP_MIN_RTO: u32 = 20;
const TCP_MAX_RETRIES: u8 = 10;
const TCP_TIME_WAIT_TICKS: u64 = 12000;
const TCP_MAX_RETX_ENTRIES = 8;

const TCPFlags = protocol.Flags;
const TCPState = protocol.State;
const TCPHeader = protocol.Header;

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
    ready: sync.Semaphore,
};

const TCPSocket = struct {
    connection: ?*TCPConnectionStruct,
    listener: ?*anyopaque,
    listening: bool,
    port: u16,
};

const MAX_TCP_CONNECTIONS = 32;
const TCP_BUFFER_SIZE = 4096;

var tcp_connections: [MAX_TCP_CONNECTIONS]?TCPConnectionStruct = [_]?TCPConnectionStruct{null} ** MAX_TCP_CONNECTIONS;
var tcp_sockets: [MAX_TCP_CONNECTIONS]?TCPSocket = [_]?TCPSocket{null} ** MAX_TCP_CONNECTIONS;

pub fn init() void {
    ipv4.registerProtocolHandler(TCP_PROTOCOL, handleTCPPacket);
    ipv6.registerProtocolHandler(NEXT_HEADER_TCP, handleTCPPacketIPv6);
}

fn notifyConnectionActivity(conn: *TCPConnectionStruct) void {
    conn.ready.signal();
    readiness.notifySocket();
}

pub fn waitForActivity(conn: *TCPConnection) void {
    conn.ready.wait();
}

pub fn isConnecting(conn: *const TCPConnection) bool {
    return conn.state == .SYN_SENT or conn.state == .SYN_RECEIVED;
}

pub fn isEstablished(conn: *const TCPConnection) bool {
    return conn.state == .ESTABLISHED;
}

pub fn isReadableClosed(conn: *const TCPConnection) bool {
    return conn.state == .CLOSED or conn.state == .CLOSE_WAIT or conn.state == .LAST_ACK or conn.state == .TIME_WAIT;
}

pub fn hasReadableData(conn: *const TCPConnection) bool {
    return conn.recv_buffer_used != 0;
}

pub fn receiveData(conn: *TCPConnection, buffer: []u8) usize {
    if (conn.recv_buffer_used == 0) return 0;

    const to_copy = @min(buffer.len, conn.recv_buffer_used);
    @memcpy(buffer[0..to_copy], conn.recv_buffer[0..to_copy]);

    if (to_copy < conn.recv_buffer_used) {
        const remaining = conn.recv_buffer_used - to_copy;
        @memcpy(conn.recv_buffer[0..remaining], conn.recv_buffer[to_copy..conn.recv_buffer_used]);
    }
    conn.recv_buffer_used -= to_copy;
    readiness.notifySocket();

    return to_copy;
}

const NEXT_HEADER_TCP: u8 = 6;

fn handleTCPPacketIPv6(src: *const ipv6.IPv6Address, dst: *const ipv6.IPv6Address, data: []const u8) void {
    if (data.len < @sizeOf(TCPHeader)) return;

    const tcp_header: *align(1) const TCPHeader = @ptrCast(data.ptr);
    const header = tcp_header.*;
    const header_len = (&header).getDataOffset();
    if (header_len < @sizeOf(TCPHeader) or header_len > data.len) return;

    var temp_header = header;
    temp_header.checksum = 0;
    const calculated = calculateChecksumIPv6(src, dst, &temp_header, data[@sizeOf(TCPHeader)..]);
    if (header.checksum != calculated) return;

    const flags = (&header).getFlags();
    const dst_port = @byteSwap(header.dst_port);

    if (flags & TCPFlags.SYN != 0) {
        if (findListeningSocket(dst_port) == null) {
            const src_port = @byteSwap(header.src_port);
            const ack = @byteSwap(header.seq_num) +% 1;
            sendRSTv6(src, dst, src_port, dst_port, ack);
        }
    }
}

fn sendRSTv6(dst: *const ipv6.IPv6Address, src: *const ipv6.IPv6Address, dst_port: u16, src_port: u16, seq_num: u32) void {
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

    tcp_header.checksum = calculateChecksumIPv6(src, dst, tcp_header, &[_]u8{});
    ipv6.sendPacket(dst.*, ipv6.NEXT_HEADER_TCP, packet[0..packet_size]);
}

const calculateChecksum = protocol.calculateChecksumIPv4;

pub fn calculateChecksumIPv6(src: *const ipv6.IPv6Address, dst: *const ipv6.IPv6Address, tcp_header: *const TCPHeader, data: []const u8) u16 {
    return protocol.calculateChecksumIPv6(&src.octets, &dst.octets, tcp_header, data);
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
        protocol.buildOptions(connection, &options_buf, is_syn)
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
                .ready = sync.Semaphore.init(0),
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

    const tcp_header: *align(1) const TCPHeader = @ptrCast(data.ptr);
    const header = tcp_header.*;
    const header_len = (&header).getDataOffset();
    if (header_len < @sizeOf(TCPHeader) or header_len > data.len) {
        return;
    }

    const checksum = header.checksum;
    var temp_header = header;
    temp_header.checksum = 0;
    const calculated_checksum = calculateChecksum(src_ip, dst_ip, &temp_header, data[@sizeOf(TCPHeader)..]);
    if (checksum != calculated_checksum) {
        vga.print("TCP: Invalid checksum\n");
        return;
    }

    const src_port = @byteSwap(header.src_port);
    const dst_port = @byteSwap(header.dst_port);
    const seq_num = @byteSwap(header.seq_num);
    const ack_num = @byteSwap(header.ack_num);
    const flags = (&header).getFlags();
    const window_size = @byteSwap(header.window_size);
    const payload = data[header_len..];

    if (findConnection(dst_ip, src_ip, dst_port, src_port)) |conn| {
        if (header_len > @sizeOf(TCPHeader)) {
            const opt_start = @sizeOf(TCPHeader);
            const opt_end = @min(header_len, data.len);
            if (opt_end > opt_start) {
                if (protocol.parseOptions(data[opt_start..opt_end], conn, @intCast(timer.getTicks() & 0xFFFFFFFF))) |rtt| {
                    updateRTT(conn, rtt);
                }
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
    protocol.applySACKBlocks(conn);

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
    if (bytes_acked > 0 and protocol.seqLessThanEq(conn.send_una, ack_num)) {
        conn.bytes_in_flight -|= bytes_acked;
        conn.send_una = ack_num;
        conn.dup_ack_count = 0;
        conn.retx_count = 0;

        for (&conn.retx_queue) |*entry| {
            if (entry.active and protocol.seqLessThanEq(entry.seq_num +% entry.data_len, ack_num)) {
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
        notifyConnectionActivity(conn);
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
                notifyConnectionActivity(conn);
            }
        },
        .SYN_RECEIVED => {
            if (flags & TCPFlags.ACK != 0) {
                conn.send_una = ack_num;
                conn.bytes_in_flight = 0;
                conn.state = .ESTABLISHED;
                clearRetxQueue(conn);
                vga.print("TCP: Connection accepted\n");
                queueAcceptedConnection(conn);
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
                    notifyConnectionActivity(conn);
                }
                sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
            }
            if (flags & TCPFlags.FIN != 0) {
                conn.recv_seq = seq_num +% @as(u32, @intCast(payload.len)) +% 1;
                conn.send_ack = conn.recv_seq;
                conn.state = .CLOSE_WAIT;
                sendTCPPacket(conn, TCPFlags.ACK, &[_]u8{}) catch {};
                notifyConnectionActivity(conn);
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
                    notifyConnectionActivity(conn);
                } else if (protocol.seqLessThanEq(conn.send_seq, ack_num)) {
                    conn.state = .FIN_WAIT_2;
                    clearRetxQueue(conn);
                    notifyConnectionActivity(conn);
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
                notifyConnectionActivity(conn);
            }
        },
        .CLOSING => {
            if (flags & TCPFlags.ACK != 0) {
                conn.state = .TIME_WAIT;
                conn.time_wait_start = timer.getTicks();
                notifyConnectionActivity(conn);
            }
        },
        .LAST_ACK => {
            if (flags & TCPFlags.ACK != 0) {
                conn.state = .CLOSED;
                clearRetxQueue(conn);
                notifyConnectionActivity(conn);
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
        releaseConnection(conn);
    };
}

fn queueAcceptedConnection(conn: *TCPConnectionStruct) void {
    const listener = findListeningSocket(conn.local_port) orelse {
        conn.state = .CLOSED;
        notifyConnectionActivity(conn);
        return;
    };

    const raw_listener = listener.listener orelse {
        conn.state = .CLOSED;
        notifyConnectionActivity(conn);
        return;
    };

    const socket_mod = @import("socket.zig");
    const listener_socket: *socket_mod.Socket = @ptrCast(@alignCast(raw_listener));
    const client = socket_mod.createAcceptedTcpSocket(
        conn,
        ipv4.IPv4Address.fromU32(conn.local_addr),
        conn.local_port,
        ipv4.IPv4Address.fromU32(conn.remote_addr),
        conn.remote_port,
    ) catch {
        conn.state = .CLOSED;
        notifyConnectionActivity(conn);
        return;
    };

    listener_socket.addToBacklog(client) catch {
        client.close();
        return;
    };

    notifyConnectionActivity(conn);
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
                .listener = null,
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
    const conn = socket.connection orelse return error.NotConnected;

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
    const conn = socket.connection orelse return error.NotConnected;
    return receiveData(conn, buffer);
}

pub fn close(socket_id: usize) !void {
    if (socket_id >= tcp_sockets.len) return error.InvalidSocket;
    const socket = &(tcp_sockets[socket_id] orelse return error.InvalidSocket);

    if (socket.connection) |conn| {
        if (conn.state == .ESTABLISHED) {
            conn.state = .FIN_WAIT_1;
            try sendTCPPacket(conn, TCPFlags.FIN | TCPFlags.ACK, &[_]u8{});
        }
        clearRetxQueue(conn);
        memory.kfree(conn.recv_buffer.ptr);
        memory.kfree(conn.send_buffer.ptr);
        notifyConnectionActivity(conn);
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
            notifyConnectionActivity(conn);
        },
        .CLOSE_WAIT => {
            conn.state = .LAST_ACK;
            sendTCPPacket(conn, TCPFlags.FIN | TCPFlags.ACK, &[_]u8{}) catch {};
            notifyConnectionActivity(conn);
        },
        else => {},
    }
}

pub fn releaseConnection(conn: *TCPConnection) void {
    clearRetxQueue(conn);
    memory.kfree(conn.recv_buffer.ptr);
    memory.kfree(conn.send_buffer.ptr);
    for (&tcp_connections) |*maybe_conn| {
        if (maybe_conn.*) |*c| {
            if (c == conn) {
                maybe_conn.* = null;
                break;
            }
        }
    }
}

pub fn tick() void {
    const now = timer.getTicks();

    for (&tcp_connections) |*maybe_conn| {
        if (maybe_conn.*) |*conn| {
            if (conn.state == .TIME_WAIT) {
                if (now - conn.time_wait_start >= TCP_TIME_WAIT_TICKS) {
                    clearRetxQueue(conn);
                    memory.kfree(conn.recv_buffer.ptr);
                    memory.kfree(conn.send_buffer.ptr);
                    maybe_conn.* = null;
                }
                continue;
            }

            if (conn.state == .CLOSED) {
                memory.kfree(conn.recv_buffer.ptr);
                memory.kfree(conn.send_buffer.ptr);
                maybe_conn.* = null;
                continue;
            }

            for (&conn.retx_queue) |*entry| {
                if (entry.active and now - entry.send_time >= conn.rto) {
                    if (entry.retries >= TCP_MAX_RETRIES) {
                        conn.state = .CLOSED;
                        clearRetxQueue(conn);
                        vga.print("TCP: Connection timed out\n");
                        notifyConnectionActivity(conn);
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

pub fn registerListeningSocket(sock: *@import("socket.zig").Socket) void {
    for (&tcp_sockets) |*maybe_socket| {
        if (maybe_socket.*) |*s| {
            if (s.listening and s.port == sock.local_port) {
                s.listener = sock;
                return;
            }
        }
    }

    for (&tcp_sockets) |*maybe_socket| {
        if (maybe_socket.* == null) {
            maybe_socket.* = TCPSocket{
                .connection = null,
                .listener = sock,
                .listening = true,
                .port = sock.local_port,
            };
            return;
        }
    }
}

pub fn unregisterListeningSocket(port: u16) void {
    for (&tcp_sockets) |*maybe_socket| {
        if (maybe_socket.*) |s| {
            if (s.listening and s.port == port) {
                maybe_socket.* = null;
                return;
            }
        }
    }
}
