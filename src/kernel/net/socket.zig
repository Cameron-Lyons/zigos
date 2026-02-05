const memory = @import("../memory/memory.zig");
const tcp = @import("tcp.zig");
const udp = @import("udp.zig");
const ipv4 = @import("ipv4.zig");
const ipv6 = @import("ipv6.zig");
const vga = @import("../drivers/vga.zig");
const process = @import("../process/process.zig");

pub const AddressFamily = enum {
    AF_INET,
    AF_INET6,
    AF_UNIX,
};

pub const SocketType = enum {
    STREAM,
    DGRAM,
    RAW,
};

pub const Protocol = enum {
    TCP,
    UDP,
    ICMP,
    RAW,
    UNIX_STREAM,
    UNIX_DGRAM,
};

pub const SocketState = enum {
    UNCONNECTED,
    LISTENING,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
    CLOSED,
};

pub const SocketError = error{
    InvalidSocket,
    InvalidAddress,
    AlreadyConnected,
    NotConnected,
    ConnectionRefused,
    ConnectionReset,
    NoBufferSpace,
    Timeout,
    AddressInUse,
    NotListening,
};

const MAX_SOCKETS = 128;
const MAX_BACKLOG = 16;
const RECV_BUFFER_SIZE = 4096;
const RECV_BUFFER_MASK = RECV_BUFFER_SIZE - 1;
const SEND_BUFFER_SIZE = 4096;
const SEND_BUFFER_MASK = SEND_BUFFER_SIZE - 1;

pub const Socket = struct {
    id: u32,
    socket_type: SocketType,
    protocol: Protocol,
    state: SocketState,
    local_addr: ipv4.IPv4Address,
    local_port: u16,
    remote_addr: ipv4.IPv4Address,
    remote_port: u16,
    owner_pid: u32,
    recv_buffer: []u8,
    recv_head: usize,
    recv_tail: usize,
    send_buffer: []u8,
    send_head: usize,
    send_tail: usize,
    backlog: []?*Socket,
    backlog_count: usize,
    tcp_connection: ?*tcp.TCPConnection,
    blocking: bool,
    in_use: bool,
    address_family: AddressFamily,
    remote_ipv6: ?ipv6.IPv6Address,
    local_ipv6: ?ipv6.IPv6Address,

    pub fn init(socket_type: SocketType, protocol: Protocol) !*Socket {
        const sock_mem = memory.kmalloc(@sizeOf(Socket)) orelse return error.OutOfMemory;
        const sock: *Socket = @ptrCast(@alignCast(sock_mem));
        sock.* = Socket{
            .id = generateSocketId(),
            .socket_type = socket_type,
            .protocol = protocol,
            .state = .UNCONNECTED,
            .local_addr = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } },
            .local_port = 0,
            .remote_addr = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } },
            .remote_port = 0,
            .owner_pid = process.getCurrentPID(),
            .recv_buffer = blk: {
                const buf = memory.kmalloc(RECV_BUFFER_SIZE) orelse return error.OutOfMemory;
                const ptr: [*]u8 = @ptrCast(@alignCast(buf));
                break :blk ptr[0..RECV_BUFFER_SIZE];
            },
            .recv_head = 0,
            .recv_tail = 0,
            .send_buffer = blk: {
                const buf = memory.kmalloc(SEND_BUFFER_SIZE) orelse return error.OutOfMemory;
                const ptr: [*]u8 = @ptrCast(@alignCast(buf));
                break :blk ptr[0..SEND_BUFFER_SIZE];
            },
            .send_head = 0,
            .send_tail = 0,
            .backlog = &[_]?*Socket{},
            .backlog_count = 0,
            .tcp_connection = null,
            .blocking = true,
            .in_use = true,
            .address_family = .AF_INET,
            .remote_ipv6 = null,
            .local_ipv6 = null,
        };
        return sock;
    }

    pub fn bind(self: *Socket, addr: ipv4.IPv4Address, port: u16) !void {
        if (self.state != .UNCONNECTED) {
            return SocketError.AlreadyConnected;
        }

        if (isPortInUse(port)) {
            return SocketError.AddressInUse;
        }

        self.local_addr = addr;
        self.local_port = port;
    }

    pub fn listen(self: *Socket, backlog: usize) !void {
        if (self.socket_type != .STREAM) {
            return SocketError.InvalidSocket;
        }

        if (self.local_port == 0) {
            return SocketError.InvalidAddress;
        }

        const backlog_size = @min(backlog, MAX_BACKLOG);
        const backlog_mem = memory.kmalloc(backlog_size * @sizeOf(?*Socket)) orelse return error.OutOfMemory;
        const backlog_ptr: [*]?*Socket = @ptrCast(@alignCast(backlog_mem));
        self.backlog = backlog_ptr[0..backlog_size];
        for (self.backlog) |*slot| {
            slot.* = null;
        }

        self.state = .LISTENING;

        if (self.protocol == .TCP) {
            tcp.registerListeningSocket(self);
        }
    }

    pub fn accept(self: *Socket) !*Socket {
        if (self.state != .LISTENING) {
            return SocketError.NotListening;
        }

        while (self.backlog_count == 0) {
            if (!self.blocking) {
                return SocketError.NoBufferSpace;
            }
            process.yield();
        }

        const client_socket = self.backlog[0].?;

        var i: usize = 0;
        while (i < self.backlog_count - 1) : (i += 1) {
            self.backlog[i] = self.backlog[i + 1];
        }
        self.backlog[self.backlog_count - 1] = null;
        self.backlog_count -= 1;

        return client_socket;
    }

    pub fn connect(self: *Socket, addr: ipv4.IPv4Address, port: u16) !void {
        if (self.state != .UNCONNECTED) {
            return SocketError.AlreadyConnected;
        }

        self.remote_addr = addr;
        self.remote_port = port;

        if (self.local_port == 0) {
            self.local_port = allocateEphemeralPort();
        }

        self.state = .CONNECTING;

        switch (self.protocol) {
            .TCP => {
                self.tcp_connection = try tcp.createConnection(
                    self.local_addr,
                    self.local_port,
                    self.remote_addr,
                    self.remote_port
                );

                try tcp.initiateConnection(self.tcp_connection.?);

                while (self.state == .CONNECTING) {
                    if (!self.blocking) {
                        return;
                    }
                    process.yield();
                }

                if (self.state != .CONNECTED) {
                    return SocketError.ConnectionRefused;
                }
            },
            .UDP => {
                self.state = .CONNECTED;
            },
            else => return SocketError.InvalidSocket,
        }
    }

    pub fn send(self: *Socket, data: []const u8) !usize {
        if (self.state != .CONNECTED and self.socket_type == .STREAM) {
            return SocketError.NotConnected;
        }

        switch (self.protocol) {
            .TCP => {
                if (self.tcp_connection) |conn| {
                    return try tcp.sendData(conn, data);
                }
                return 0;
            },
            .UDP => {
                try udp.send(
                    self.local_addr,
                    self.local_port,
                    self.remote_addr,
                    self.remote_port,
                    data
                );
                return data.len;
            },
            else => return 0,
        }
    }

    pub fn sendTo(self: *Socket, data: []const u8, addr: ipv4.IPv4Address, port: u16) !void {
        if (self.socket_type != .DGRAM) {
            return SocketError.InvalidSocket;
        }

        switch (self.protocol) {
            .UDP => {
                try udp.send(
                    self.local_addr,
                    self.local_port,
                    addr,
                    port,
                    data
                );
            },
            else => return SocketError.InvalidSocket,
        }
    }

    pub fn recvFrom(self: *Socket, buffer: []u8, src_addr: *ipv4.IPv4Address, src_port: *u16) !usize {
        if (self.socket_type != .DGRAM) {
            return SocketError.InvalidSocket;
        }

        while (self.recv_head == self.recv_tail) {
            if (!self.blocking) {
                return 0;
            }
            process.yield();
        }

        var bytes_read: usize = 0;
        while (bytes_read < buffer.len and self.recv_head != self.recv_tail) {
            buffer[bytes_read] = self.recv_buffer[self.recv_tail];
            self.recv_tail = (self.recv_tail + 1) & RECV_BUFFER_MASK;
            bytes_read += 1;
        }

        src_addr.* = self.remote_addr;
        src_port.* = self.remote_port;

        return bytes_read;
    }

    pub fn recv(self: *Socket, buffer: []u8) !usize {
        if (self.state != .CONNECTED and self.socket_type == .STREAM) {
            return SocketError.NotConnected;
        }

        while (self.recv_head == self.recv_tail) {
            if (!self.blocking) {
                return 0;
            }
            process.yield();
        }

        var bytes_read: usize = 0;
        while (bytes_read < buffer.len and self.recv_head != self.recv_tail) {
            buffer[bytes_read] = self.recv_buffer[self.recv_tail];
            self.recv_tail = (self.recv_tail + 1) & RECV_BUFFER_MASK;
            bytes_read += 1;
        }

        return bytes_read;
    }

    pub fn close(self: *Socket) void {
        switch (self.protocol) {
            .TCP => {
                if (self.tcp_connection) |conn| {
                    tcp.closeConnection(conn);
                }
            },
            else => {},
        }

        self.state = .CLOSED;
        self.in_use = false;
        socket_id_lookup[self.id % MAX_SOCKETS] = null;

        memory.kfree(self.recv_buffer.ptr);
        memory.kfree(self.send_buffer.ptr);
        if (self.backlog.len > 0) {
            memory.kfree(@as(*anyopaque, @ptrCast(self.backlog.ptr)));
        }
    }

    pub fn addToRecvBuffer(self: *Socket, data: []const u8) void {
        for (data) |byte| {
            const next_head = (self.recv_head + 1) & RECV_BUFFER_MASK;
            if (next_head != self.recv_tail) {
                self.recv_buffer[self.recv_head] = byte;
                self.recv_head = next_head;
            }
        }
    }

    pub fn addToBacklog(self: *Socket, client: *Socket) !void {
        if (self.backlog_count >= self.backlog.len) {
            return SocketError.NoBufferSpace;
        }

        self.backlog[self.backlog_count] = client;
        self.backlog_count += 1;
    }
};

var sockets: [MAX_SOCKETS]?*Socket = [_]?*Socket{null} ** MAX_SOCKETS;
var socket_id_lookup: [MAX_SOCKETS]?*Socket = [_]?*Socket{null} ** MAX_SOCKETS;
var next_socket_id: u32 = 1;
var next_ephemeral_port: u16 = 49152;

fn generateSocketId() u32 {
    const id = next_socket_id;
    next_socket_id += 1;
    return id;
}

fn allocateEphemeralPort() u16 {
    const port = next_ephemeral_port;
    next_ephemeral_port += 1;
    if (next_ephemeral_port > 65535) {
        next_ephemeral_port = 49152;
    }
    return port;
}

fn isPortInUse(port: u16) bool {
    for (sockets) |maybe_sock| {
        if (maybe_sock) |sock| {
            if (sock.in_use and sock.local_port == port) {
                return true;
            }
        }
    }
    return false;
}

pub fn createSocket(socket_type: SocketType, protocol: Protocol) !*Socket {
    const sock = try Socket.init(socket_type, protocol);

    for (&sockets) |*slot| {
        if (slot.* == null) {
            slot.* = sock;
            socket_id_lookup[sock.id % MAX_SOCKETS] = sock;
            return sock;
        }
    }

    return SocketError.NoBufferSpace;
}

pub fn findSocket(id: u32) ?*Socket {
    const slot = id % MAX_SOCKETS;
    if (socket_id_lookup[slot]) |sock| {
        if (sock.id == id and sock.in_use) {
            return sock;
        }
    }
    return null;
}

pub fn findListeningSocket(port: u16) ?*Socket {
    for (sockets) |maybe_sock| {
        if (maybe_sock) |sock| {
            if (sock.in_use and sock.local_port == port and sock.state == .LISTENING) {
                return sock;
            }
        }
    }
    return null;
}

pub fn init() void {
    vga.print("Socket API initialized\n");
}