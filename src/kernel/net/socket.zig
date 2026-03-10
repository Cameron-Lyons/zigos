const memory = @import("../memory/memory.zig");
const tcp = @import("tcp.zig");
const udp = @import("udp.zig");
const ipv4 = @import("ipv4.zig");
const ipv6 = @import("ipv6.zig");
const vga = @import("../drivers/vga.zig");
const process = @import("../process/process.zig");
const readiness = @import("../process/syscall/readiness.zig");
const sync = @import("../utils/sync.zig");

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

pub const POLLIN: u16 = 0x001;
pub const POLLOUT: u16 = 0x004;

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
    backlog_head: usize,
    backlog_tail: usize,
    tcp_connection: ?*tcp.TCPConnection,
    blocking: bool,
    in_use: bool,
    address_family: AddressFamily,
    remote_ipv6: ?ipv6.IPv6Address,
    local_ipv6: ?ipv6.IPv6Address,
    recv_ready: sync.Semaphore,
    accept_ready: sync.Semaphore,
    state_ready: sync.Semaphore,

    pub fn init(socket_type: SocketType, protocol: Protocol) !*Socket {
        const sock_mem = memory.kmalloc(@sizeOf(Socket)) orelse return error.OutOfMemory;
        errdefer memory.kfree(@as([*]u8, @ptrCast(sock_mem)));

        const recv_buf = memory.kmalloc(RECV_BUFFER_SIZE) orelse return error.OutOfMemory;
        errdefer memory.kfree(@as([*]u8, @ptrCast(recv_buf)));

        const send_buf = memory.kmalloc(SEND_BUFFER_SIZE) orelse return error.OutOfMemory;
        errdefer memory.kfree(@as([*]u8, @ptrCast(send_buf)));

        const recv_ptr: [*]u8 = @ptrCast(@alignCast(recv_buf));
        const send_ptr: [*]u8 = @ptrCast(@alignCast(send_buf));

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
            .recv_buffer = recv_ptr[0..RECV_BUFFER_SIZE],
            .recv_head = 0,
            .recv_tail = 0,
            .send_buffer = send_ptr[0..SEND_BUFFER_SIZE],
            .send_head = 0,
            .send_tail = 0,
            .backlog = &[_]?*Socket{},
            .backlog_count = 0,
            .backlog_head = 0,
            .backlog_tail = 0,
            .tcp_connection = null,
            .blocking = true,
            .in_use = true,
            .address_family = .AF_INET,
            .remote_ipv6 = null,
            .local_ipv6 = null,
            .recv_ready = sync.Semaphore.init(0),
            .accept_ready = sync.Semaphore.init(0),
            .state_ready = sync.Semaphore.init(0),
        };
        return sock;
    }

    pub fn setState(self: *Socket, state: SocketState) void {
        self.state = state;
        self.state_ready.signal();
        readiness.notifyAll();
    }

    pub fn pollEvents(self: *const Socket, requested_events: u16) u16 {
        var ready: u16 = 0;

        if ((requested_events & POLLIN) != 0) {
            if (self.state == .LISTENING) {
                if (self.backlog_count > 0) {
                    ready |= POLLIN;
                }
            } else if (self.protocol == .TCP) {
                if (self.tcp_connection) |conn| {
                    if (tcp.hasReadableData(conn) or tcp.isReadableClosed(conn)) {
                        ready |= POLLIN;
                    }
                } else if (self.state == .CLOSED) {
                    ready |= POLLIN;
                }
            } else if (self.recv_head != self.recv_tail or self.state == .CLOSED) {
                ready |= POLLIN;
            }
        }

        if ((requested_events & POLLOUT) != 0) {
            switch (self.protocol) {
                .TCP => {
                    if (self.state == .CONNECTED) {
                        ready |= POLLOUT;
                    } else if (self.state == .CONNECTING) {
                        if (self.tcp_connection) |conn| {
                            if (!tcp.isConnecting(conn)) {
                                ready |= POLLOUT;
                            }
                        }
                    }
                },
                else => {
                    if (self.state != .CLOSED and self.state != .LISTENING) {
                        ready |= POLLOUT;
                    }
                },
            }
        }

        return ready;
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
        port_lookup[port % PORT_LOOKUP_SIZE] = self;
    }

    pub fn listen(self: *Socket, backlog: usize) !void {
        if (self.socket_type != .STREAM) {
            return SocketError.InvalidSocket;
        }

        if (self.local_port == 0) {
            return SocketError.InvalidAddress;
        }

        if (self.backlog.len > 0) {
            memory.kfree(@as(*anyopaque, @ptrCast(self.backlog.ptr)));
        }

        const backlog_size = @max(@as(usize, 1), @min(backlog, MAX_BACKLOG));
        const backlog_mem = memory.kmalloc(backlog_size * @sizeOf(?*Socket)) orelse return error.OutOfMemory;
        const backlog_ptr: [*]?*Socket = @ptrCast(@alignCast(backlog_mem));
        self.backlog = backlog_ptr[0..backlog_size];
        for (self.backlog) |*slot| {
            slot.* = null;
        }
        self.backlog_count = 0;
        self.backlog_head = 0;
        self.backlog_tail = 0;

        self.setState(.LISTENING);

        if (self.protocol == .TCP) {
            tcp.registerListeningSocket(self);
        }
    }

    pub fn accept(self: *Socket) !*Socket {
        if (self.state != .LISTENING) {
            return SocketError.NotListening;
        }

        while (self.backlog_count == 0) {
            if (self.state != .LISTENING) {
                return SocketError.NotListening;
            }
            if (!self.blocking) {
                return SocketError.NoBufferSpace;
            }
            self.accept_ready.wait();
        }

        const client_socket = self.backlog[self.backlog_head].?;
        self.backlog[self.backlog_head] = null;
        self.backlog_head = (self.backlog_head + 1) % self.backlog.len;
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

        self.setState(.CONNECTING);

        switch (self.protocol) {
            .TCP => {
                self.tcp_connection = try tcp.createConnection(self.local_addr, self.local_port, self.remote_addr, self.remote_port);

                try tcp.initiateConnection(self.tcp_connection.?);

                while (tcp.isConnecting(self.tcp_connection.?)) {
                    if (!self.blocking) {
                        return;
                    }
                    tcp.waitForActivity(self.tcp_connection.?);
                }

                if (!tcp.isEstablished(self.tcp_connection.?)) {
                    self.setState(.CLOSED);
                    return SocketError.ConnectionRefused;
                }
                self.setState(.CONNECTED);
            },
            .UDP => {
                self.setState(.CONNECTED);
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
                try udp.send(self.local_addr, self.local_port, self.remote_addr, self.remote_port, data);
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
                try udp.send(self.local_addr, self.local_port, addr, port, data);
            },
            else => return SocketError.InvalidSocket,
        }
    }

    pub fn recvFrom(self: *Socket, buffer: []u8, src_addr: *ipv4.IPv4Address, src_port: *u16) !usize {
        if (self.socket_type != .DGRAM) {
            return SocketError.InvalidSocket;
        }

        while (self.recv_head == self.recv_tail) {
            if (self.state == .CLOSED) {
                return 0;
            }
            if (!self.blocking) {
                return 0;
            }
            self.recv_ready.wait();
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

        if (self.protocol == .TCP) {
            const conn = self.tcp_connection orelse return SocketError.NotConnected;

            while (!tcp.hasReadableData(conn)) {
                if (tcp.isReadableClosed(conn)) {
                    return 0;
                }
                if (!self.blocking) {
                    return 0;
                }
                tcp.waitForActivity(conn);
            }

            return tcp.receiveData(conn, buffer);
        }

        while (self.recv_head == self.recv_tail) {
            if (self.state == .CLOSED) {
                return 0;
            }
            if (!self.blocking) {
                return 0;
            }
            self.recv_ready.wait();
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
                    tcp.releaseConnection(conn);
                }
                if (self.state == .LISTENING and self.local_port != 0) {
                    tcp.unregisterListeningSocket(self.local_port);
                }
            },
            else => {},
        }

        self.setState(.CLOSED);
        self.recv_ready.signal();
        self.accept_ready.signal();
        self.state_ready.signal();
        self.in_use = false;
        socket_id_lookup[self.id % MAX_SOCKETS] = null;
        if (self.local_port != 0) {
            port_lookup[self.local_port % PORT_LOOKUP_SIZE] = null;
        }

        for (&sockets) |*slot| {
            if (slot.* == self) {
                slot.* = null;
                break;
            }
        }

        memory.kfree(self.recv_buffer.ptr);
        memory.kfree(self.send_buffer.ptr);
        if (self.backlog.len > 0) {
            var i: usize = 0;
            var idx = self.backlog_head;
            while (i < self.backlog_count) : (i += 1) {
                const maybe_client = self.backlog[idx];
                self.backlog[idx] = null;
                if (maybe_client) |client| {
                    client.close();
                }
                idx = (idx + 1) % self.backlog.len;
            }
            memory.kfree(@as(*anyopaque, @ptrCast(self.backlog.ptr)));
        }
        memory.kfree(@as([*]u8, @ptrCast(self)));
    }

    pub fn addToRecvBuffer(self: *Socket, data: []const u8) void {
        for (data) |byte| {
            const next_head = (self.recv_head + 1) & RECV_BUFFER_MASK;
            if (next_head != self.recv_tail) {
                self.recv_buffer[self.recv_head] = byte;
                self.recv_head = next_head;
            }
        }
        self.recv_ready.signal();
        readiness.notifyAll();
    }

    pub fn addToBacklog(self: *Socket, client: *Socket) !void {
        if (self.backlog_count >= self.backlog.len) {
            return SocketError.NoBufferSpace;
        }

        self.backlog[self.backlog_tail] = client;
        self.backlog_tail = (self.backlog_tail + 1) % self.backlog.len;
        self.backlog_count += 1;
        self.accept_ready.signal();
        readiness.notifyAll();
    }
};

var sockets: [MAX_SOCKETS]?*Socket = [_]?*Socket{null} ** MAX_SOCKETS;
var socket_id_lookup: [MAX_SOCKETS]?*Socket = [_]?*Socket{null} ** MAX_SOCKETS;
const PORT_LOOKUP_SIZE = 1024;
var port_lookup: [PORT_LOOKUP_SIZE]?*Socket = [_]?*Socket{null} ** PORT_LOOKUP_SIZE;
var next_socket_id: u32 = 1;
var next_ephemeral_port: u16 = 49152;

fn generateSocketId() u32 {
    const id = next_socket_id;
    next_socket_id += 1;
    return id;
}

fn allocateEphemeralPort() u16 {
    const port = next_ephemeral_port;
    next_ephemeral_port +%= 1;
    if (next_ephemeral_port < 49152) {
        next_ephemeral_port = 49152;
    }
    return port;
}

fn isPortInUse(port: u16) bool {
    const slot = port % PORT_LOOKUP_SIZE;
    if (port_lookup[slot]) |sock| {
        if (sock.in_use and sock.local_port == port) {
            return true;
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

    memory.kfree(sock.recv_buffer.ptr);
    memory.kfree(sock.send_buffer.ptr);
    memory.kfree(@as([*]u8, @ptrCast(sock)));
    return SocketError.NoBufferSpace;
}

pub fn createAcceptedTcpSocket(
    conn: *tcp.TCPConnection,
    local_addr: ipv4.IPv4Address,
    local_port: u16,
    remote_addr: ipv4.IPv4Address,
    remote_port: u16,
) !*Socket {
    const sock = try createSocket(.STREAM, .TCP);
    sock.local_addr = local_addr;
    sock.local_port = local_port;
    sock.remote_addr = remote_addr;
    sock.remote_port = remote_port;
    sock.tcp_connection = conn;
    sock.state = .CONNECTED;
    return sock;
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
    const slot = port % PORT_LOOKUP_SIZE;
    if (port_lookup[slot]) |sock| {
        if (sock.in_use and sock.local_port == port and sock.state == .LISTENING) {
            return sock;
        }
    }
    return null;
}

pub fn init() void {
    vga.print("Socket API initialized\n");
}
