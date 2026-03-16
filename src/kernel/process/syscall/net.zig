const std = @import("std");
const abi = @import("abi.zig");
const errno = @import("errno.zig");
const ipv4 = @import("../../net/ipv4.zig");
const ipv6 = @import("../../net/ipv6.zig");
const protection = @import("../../memory/protection.zig");
const readiness = @import("readiness.zig");
const socket = @import("../../net/socket.zig");

pub const AF_UNIX: u32 = 1;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;

pub const socket_fd_base: i32 = 500;
pub const unix_socket_fd_base: i32 = 700;
pub const socket_count: usize = 64;
pub const unix_socket_count: usize = 64;
pub const SOCKET_TRANSFER_BUFFER_SIZE: usize = 4096;
pub const UNIX_SOCKET_BUFFER_SIZE: usize = SOCKET_TRANSFER_BUFFER_SIZE;
const UNIX_SOCKET_BUFFER_MASK: usize = UNIX_SOCKET_BUFFER_SIZE - 1;

const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;
const SOL_SOCKET: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const SO_REUSEADDR: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_BROADCAST: i32 = 6;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;
const SO_KEEPALIVE: i32 = 9;
const SO_LINGER: i32 = 13;
const SO_RCVTIMEO: i32 = 20;
const SO_SNDTIMEO: i32 = 21;
const TCP_NODELAY: i32 = 1;

pub const SockAddrIn = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};

pub const SockAddrIn6 = extern struct {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [16]u8,
    scope_id: u32,
};

pub const SockAddrUn = extern struct {
    family: u16,
    path: [108]u8,
};

pub const IPv4Endpoint = struct {
    addr: ipv4.IPv4Address,
    port: u16,
};

pub const IPv6Endpoint = struct {
    addr: ipv6.IPv6Address,
    port: u16,
};

pub const UnixSocket = struct {
    path: [108]u8,
    path_len: usize,
    peer: ?*UnixSocket,
    recv_buffer: [UNIX_SOCKET_BUFFER_SIZE]u8,
    recv_head: usize,
    recv_tail: usize,
    recv_count: usize,
    listening: bool,
    connected: bool,
    in_use: bool,
};

pub const SocketTable = [64]?*socket.Socket;
pub const UnixSocketTable = [unix_socket_count]UnixSocket;

var attached_unix_sockets: ?*UnixSocketTable = null;
var attached_socket_table: ?*SocketTable = null;

pub fn attachTables(unix_sockets: *UnixSocketTable, socket_table: *SocketTable) void {
    attached_unix_sockets = unix_sockets;
    attached_socket_table = socket_table;
}

pub fn isInetSocketFd(fd: i32) bool {
    return fd >= socket_fd_base and fd < socket_fd_base + @as(i32, @intCast(socket_count));
}

pub fn isUnixSocketFd(fd: i32) bool {
    return fd >= unix_socket_fd_base and fd < unix_socket_fd_base + @as(i32, @intCast(unix_socket_count));
}

pub fn isSocketFd(fd: i32) bool {
    return isInetSocketFd(fd) or isUnixSocketFd(fd);
}

pub fn getInetSocket(fd: i32) ?*socket.Socket {
    const idx = inetSocketIndex(fd) orelse return null;
    const socket_table = attached_socket_table orelse return null;
    return socket_table[idx];
}

pub fn getUnixSocket(fd: i32) ?*UnixSocket {
    const idx = unixSocketIndex(fd) orelse return null;
    const unix_sockets = attached_unix_sockets orelse return null;
    const usock = &unix_sockets[idx];
    if (!usock.in_use) return null;
    return usock;
}

pub fn parseSockAddrIn(addr_ptr: usize, addr_len: u32) ?IPv4Endpoint {
    if (addr_len < @sizeOf(SockAddrIn)) return null;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return null;

    var addr_buf: [@sizeOf(SockAddrIn)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return null;
    const addr: *const SockAddrIn = @ptrCast(@alignCast(&addr_buf));

    return .{
        .addr = .{
            .octets = .{
                @intCast((addr.addr >> 0) & 0xFF),
                @intCast((addr.addr >> 8) & 0xFF),
                @intCast((addr.addr >> 16) & 0xFF),
                @intCast((addr.addr >> 24) & 0xFF),
            },
        },
        .port = @byteSwap(addr.port),
    };
}

pub fn parseSockAddrIn6(addr_ptr: usize, addr_len: u32) ?IPv6Endpoint {
    if (addr_len < @sizeOf(SockAddrIn6)) return null;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return null;

    var addr_buf: [@sizeOf(SockAddrIn6)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return null;
    const addr: *const SockAddrIn6 = @ptrCast(@alignCast(&addr_buf));

    return .{
        .addr = .{ .octets = addr.addr },
        .port = @byteSwap(addr.port),
    };
}

pub fn writeSockAddrIn(addr_ptr: usize, len_ptr: usize, endpoint: IPv4Endpoint) i32 {
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return abi.EINVAL;

    const addr = SockAddrIn{
        .family = @intCast(AF_INET),
        .port = @byteSwap(endpoint.port),
        .addr = @as(u32, endpoint.addr.octets[0]) |
            (@as(u32, endpoint.addr.octets[1]) << 8) |
            (@as(u32, endpoint.addr.octets[2]) << 16) |
            (@as(u32, endpoint.addr.octets[3]) << 24),
        .zero = [_]u8{0} ** 8,
    };

    protection.copyToUser(addr_ptr, std.mem.asBytes(&addr)) catch return abi.EINVAL;
    writeSockAddrLen(len_ptr, @sizeOf(SockAddrIn));
    return 0;
}

pub fn writeSockAddrIn6(addr_ptr: usize, len_ptr: usize, endpoint: IPv6Endpoint) i32 {
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return abi.EINVAL;

    const addr = SockAddrIn6{
        .family = @intCast(AF_INET6),
        .port = @byteSwap(endpoint.port),
        .flowinfo = 0,
        .addr = endpoint.addr.octets,
        .scope_id = 0,
    };

    protection.copyToUser(addr_ptr, std.mem.asBytes(&addr)) catch return abi.EINVAL;
    writeSockAddrLen(len_ptr, @sizeOf(SockAddrIn6));
    return 0;
}

pub fn pollSocketFd(fd: i32, requested_events: u16) error{BadFd}!u16 {
    if (getInetSocket(fd)) |sock| {
        return sock.pollEvents(requested_events);
    }

    if (getUnixSocket(fd)) |usock| {
        return pollUnixSocket(usock, requested_events);
    }

    return error.BadFd;
}

pub fn writeSocketFd(fd: i32, buffer: []const u8) ?i32 {
    if (getInetSocket(fd)) |sock| {
        const sent = sock.send(buffer) catch |err| return errno.socketErrno(err);
        return @intCast(sent);
    }

    if (getUnixSocket(fd)) |usock| {
        return writeUnixSocket(usock, buffer);
    }

    return null;
}

fn writeSockAddrLen(len_ptr: usize, len: u32) void {
    if (len_ptr != 0 and protection.verifyUserPointer(len_ptr, @sizeOf(u32))) {
        var value = len;
        protection.copyToUser(len_ptr, std.mem.asBytes(&value)) catch {};
    }
}

pub fn readSocketFd(fd: i32, buffer: []u8) ?i32 {
    if (getInetSocket(fd)) |sock| {
        const received = sock.recv(buffer) catch |err| return errno.socketErrno(err);
        return @intCast(received);
    }

    if (getUnixSocket(fd)) |usock| {
        return readUnixSocket(usock, buffer);
    }

    return null;
}

pub fn closeSocketFd(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, fd: i32) ?i32 {
    if (inetSocketIndex(fd)) |idx| {
        if (socket_table[idx]) |sock| {
            sock.close();
            socket_table[idx] = null;
            readiness.notifySocket();
            return 0;
        }
        return abi.EBADF;
    }

    if (unixSocketIndex(fd)) |idx| {
        var usock = &unix_sockets[idx];
        if (!usock.in_use) return abi.EBADF;
        if (usock.peer) |peer| {
            peer.peer = null;
            peer.connected = false;
        }
        usock.in_use = false;
        usock.peer = null;
        usock.path_len = 0;
        usock.listening = false;
        usock.connected = false;
        usock.recv_head = 0;
        usock.recv_tail = 0;
        usock.recv_count = 0;
        readiness.notifySocket();
        return 0;
    }

    return null;
}

fn inetSocketIndex(fd: i32) ?usize {
    if (!isInetSocketFd(fd)) return null;
    return @intCast(fd - socket_fd_base);
}

fn unixSocketIndex(fd: i32) ?usize {
    if (!isUnixSocketFd(fd)) return null;
    return @intCast(fd - unix_socket_fd_base);
}

fn pollUnixSocket(usock: *const UnixSocket, requested_events: u16) u16 {
    var ready: u16 = 0;

    if ((requested_events & POLLIN) != 0) {
        if (usock.listening) {
            if (hasPendingUnixConnection(usock)) {
                ready |= POLLIN;
            }
        } else if (usock.recv_count > 0 or (usock.connected and usock.peer == null)) {
            ready |= POLLIN;
        }
    }

    if ((requested_events & POLLOUT) != 0 and usock.connected) {
        if (usock.peer) |peer| {
            if (peer.recv_count < peer.recv_buffer.len) {
                ready |= POLLOUT;
            }
        }
    }

    return ready;
}

fn hasPendingUnixConnection(listener: *const UnixSocket) bool {
    const unix_sockets = attached_unix_sockets orelse return false;
    for (unix_sockets.*) |peer| {
        if (peer.in_use and peer.connected and peer.peer == listener) {
            return true;
        }
    }
    return false;
}

fn writeUnixSocket(usock: *UnixSocket, buffer: []const u8) i32 {
    if (!usock.in_use or !usock.connected) return abi.EBADF;

    const peer = usock.peer orelse return abi.ENOTCONN;
    const available = peer.recv_buffer.len - peer.recv_count;
    const copy_len = @min(buffer.len, available);
    if (copy_len == 0) return abi.EAGAIN;

    const first_chunk = @min(copy_len, peer.recv_buffer.len - peer.recv_tail);
    @memcpy(peer.recv_buffer[peer.recv_tail .. peer.recv_tail + first_chunk], buffer[0..first_chunk]);

    const second_chunk = copy_len - first_chunk;
    if (second_chunk != 0) {
        @memcpy(peer.recv_buffer[0..second_chunk], buffer[first_chunk..copy_len]);
    }

    peer.recv_tail = (peer.recv_tail + copy_len) & UNIX_SOCKET_BUFFER_MASK;
    peer.recv_count += copy_len;
    readiness.notifySocket();
    return @intCast(copy_len);
}

fn readUnixSocket(usock: *UnixSocket, buffer: []u8) i32 {
    if (!usock.in_use) return abi.EBADF;
    if (usock.recv_count == 0) return 0;

    const to_recv = @min(buffer.len, usock.recv_count);
    const first_chunk = @min(to_recv, usock.recv_buffer.len - usock.recv_head);
    @memcpy(buffer[0..first_chunk], usock.recv_buffer[usock.recv_head .. usock.recv_head + first_chunk]);

    const second_chunk = to_recv - first_chunk;
    if (second_chunk != 0) {
        @memcpy(buffer[first_chunk..to_recv], usock.recv_buffer[0..second_chunk]);
    }

    usock.recv_head = (usock.recv_head + to_recv) & UNIX_SOCKET_BUFFER_MASK;
    usock.recv_count -= to_recv;
    readiness.notifySocket();
    return @intCast(to_recv);
}

pub fn sys_socket(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, domain: u32, sock_type: u32, protocol: u32) i32 {
    _ = protocol;

    if (domain == AF_UNIX) {
        for (0..unix_socket_count) |i| {
            const usock = &unix_sockets[i];
            if (!usock.in_use) {
                usock.in_use = true;
                usock.path_len = 0;
                usock.peer = null;
                usock.recv_head = 0;
                usock.recv_tail = 0;
                usock.recv_count = 0;
                usock.listening = false;
                usock.connected = false;
                return @intCast(@as(i32, @intCast(i)) + unix_socket_fd_base);
            }
        }
        return abi.EMFILE;
    }

    const addr_family: socket.AddressFamily = switch (domain) {
        AF_INET => .AF_INET,
        AF_INET6 => .AF_INET6,
        else => return abi.EAFNOSUPPORT,
    };

    const s_type: socket.SocketType = switch (sock_type) {
        SOCK_STREAM => .STREAM,
        SOCK_DGRAM => .DGRAM,
        else => return abi.EINVAL,
    };

    const s_proto: socket.Protocol = switch (sock_type) {
        SOCK_STREAM => .TCP,
        SOCK_DGRAM => .UDP,
        else => return abi.EINVAL,
    };

    const sock = socket.createSocket(s_type, s_proto) catch return abi.ENOMEM;
    sock.address_family = addr_family;

    for (0..socket_table.len) |i| {
        if (socket_table[i] == null) {
            socket_table[i] = sock;
            return @intCast(@as(i32, @intCast(i)) + socket_fd_base);
        }
    }

    sock.close();
    return abi.EMFILE;
}

pub fn sys_bind(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + @as(i32, @intCast(unix_socket_count))) {
        const idx: usize = @intCast(sockfd - unix_socket_fd_base);
        const usock = &unix_sockets[idx];
        if (!usock.in_use) return abi.EBADF;

        if (addr_len < 3) return abi.EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @min(addr_len, @sizeOf(SockAddrUn)))) return abi.EINVAL;

        var addr_buf: [@sizeOf(SockAddrUn)]u8 = undefined;
        const copy_len = @min(addr_len, @sizeOf(SockAddrUn));
        protection.copyFromUser(addr_buf[0..copy_len], addr_ptr) catch return abi.EINVAL;
        const addr: *const SockAddrUn = @ptrCast(@alignCast(&addr_buf));

        const path_end = std.mem.indexOfScalar(u8, &addr.path, 0) orelse addr.path.len;
        @memcpy(usock.path[0..path_end], addr.path[0..path_end]);
        usock.path_len = path_end;
        return 0;
    }

    const sock_idx = inetSocketIndex(sockfd) orelse return abi.EBADF;
    const sock = socket_table[sock_idx] orelse return abi.EBADF;

    if (sock.address_family == .AF_INET6) {
        const endpoint = parseSockAddrIn6(addr_ptr, addr_len) orelse return abi.EINVAL;
        sock.local_ipv6 = endpoint.addr;
        sock.local_port = endpoint.port;
        return 0;
    }

    const endpoint = parseSockAddrIn(addr_ptr, addr_len) orelse return abi.EINVAL;
    sock.bind(endpoint.addr, endpoint.port) catch |err| return errno.socketErrno(err);
    return 0;
}

pub fn sys_connect(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + @as(i32, @intCast(unix_socket_count))) {
        const idx: usize = @intCast(sockfd - unix_socket_fd_base);
        const usock = &unix_sockets[idx];
        if (!usock.in_use) return abi.EBADF;

        if (addr_len < 3) return abi.EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @min(addr_len, @sizeOf(SockAddrUn)))) return abi.EINVAL;

        var addr_buf: [@sizeOf(SockAddrUn)]u8 = undefined;
        const copy_len = @min(addr_len, @sizeOf(SockAddrUn));
        protection.copyFromUser(addr_buf[0..copy_len], addr_ptr) catch return abi.EINVAL;
        const addr: *const SockAddrUn = @ptrCast(@alignCast(&addr_buf));

        const path_end = std.mem.indexOfScalar(u8, &addr.path, 0) orelse addr.path.len;

        for (0..unix_socket_count) |i| {
            const peer = &unix_sockets[i];
            if (peer.in_use and peer.listening and peer.path_len == path_end) {
                if (std.mem.eql(u8, peer.path[0..path_end], addr.path[0..path_end])) {
                    usock.peer = peer;
                    usock.connected = true;
                    readiness.notifySocket();
                    return 0;
                }
            }
        }
        return abi.ECONNREFUSED;
    }

    const sock_idx = inetSocketIndex(sockfd) orelse return abi.EBADF;
    const sock = socket_table[sock_idx] orelse return abi.EBADF;

    if (sock.address_family == .AF_INET6) {
        const endpoint = parseSockAddrIn6(addr_ptr, addr_len) orelse return abi.EINVAL;
        sock.remote_ipv6 = endpoint.addr;
        sock.remote_port = endpoint.port;
        sock.setState(.CONNECTED);
        return 0;
    }

    const endpoint = parseSockAddrIn(addr_ptr, addr_len) orelse return abi.EINVAL;
    sock.connect(endpoint.addr, endpoint.port) catch |err| return errno.socketErrno(err);
    return 0;
}

pub fn sys_listen(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, backlog: u32) i32 {
    _ = backlog;
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + @as(i32, @intCast(unix_socket_count))) {
        const idx: usize = @intCast(sockfd - unix_socket_fd_base);
        const usock = &unix_sockets[idx];
        if (!usock.in_use) return abi.EBADF;
        usock.listening = true;
        readiness.notifySocket();
        return 0;
    }

    const sock_idx = inetSocketIndex(sockfd) orelse return abi.EBADF;
    const sock = socket_table[sock_idx] orelse return abi.EBADF;
    sock.listen(5) catch |err| return errno.socketErrno(err);
    return 0;
}

pub fn sys_accept(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32) i32 {
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + @as(i32, @intCast(unix_socket_count))) {
        const idx: usize = @intCast(sockfd - unix_socket_fd_base);
        const usock = &unix_sockets[idx];
        if (!usock.in_use or !usock.listening) return abi.EBADF;

        for (0..unix_socket_count) |i| {
            const peer = &unix_sockets[i];
            if (peer.in_use and peer.connected and peer.peer == usock) {
                for (0..unix_socket_count) |j| {
                    const new_sock = &unix_sockets[j];
                    if (!new_sock.in_use) {
                        new_sock.in_use = true;
                        new_sock.connected = true;
                        new_sock.peer = peer;
                        peer.peer = new_sock;
                        readiness.notifySocket();
                        return @intCast(@as(i32, @intCast(j)) + unix_socket_fd_base);
                    }
                }
                return abi.EMFILE;
            }
        }
        return abi.EAGAIN;
    }

    const sock_idx = inetSocketIndex(sockfd) orelse return abi.EBADF;
    const sock = socket_table[sock_idx] orelse return abi.EBADF;

    const client = sock.accept() catch |err| return errno.socketErrno(err);

    for (0..socket_table.len) |i| {
        if (socket_table[i] == null) {
            socket_table[i] = client;
            readiness.notifySocket();
            return @intCast(@as(i32, @intCast(i)) + socket_fd_base);
        }
    }

    client.close();
    return abi.EMFILE;
}

pub fn sys_send(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, buf: [*]const u8, len: usize) i32 {
    _ = unix_sockets;
    _ = socket_table;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return abi.EINVAL;

    var kernel_buffer: [SOCKET_TRANSFER_BUFFER_SIZE]u8 = undefined;
    const to_send = @min(len, kernel_buffer.len);
    protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return abi.EINVAL;

    return writeSocketFd(sockfd, kernel_buffer[0..to_send]) orelse abi.EBADF;
}

pub fn sys_recv(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, buf: [*]u8, len: usize) i32 {
    _ = unix_sockets;
    _ = socket_table;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return abi.EINVAL;

    var kernel_buffer: [SOCKET_TRANSFER_BUFFER_SIZE]u8 = undefined;
    const to_recv = @min(len, kernel_buffer.len);

    const received = readSocketFd(sockfd, kernel_buffer[0..to_recv]) orelse return abi.EBADF;
    if (received == 0) return 0;
    if (received < 0) return received;

    protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..@intCast(received)]) catch return abi.EINVAL;
    return received;
}

pub fn sys_shutdown(socket_table: *SocketTable, sockfd: i32) i32 {
    const sock_idx = inetSocketIndex(sockfd) orelse return abi.EBADF;
    const sock = socket_table[sock_idx] orelse return abi.EBADF;
    sock.close();
    socket_table[sock_idx] = null;
    readiness.notifySocket();
    return 0;
}

pub fn sys_sendto(sockfd: i32, buf: [*]const u8, len: usize, dest_addr: usize, addr_len: u32) i32 {
    const sock = getInetSocket(sockfd) orelse return abi.EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return abi.EINVAL;

    var kernel_buffer: [SOCKET_TRANSFER_BUFFER_SIZE]u8 = undefined;
    const to_send = @min(len, kernel_buffer.len);
    protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return abi.EINVAL;

    if (dest_addr == 0) {
        if (sock.address_family == .AF_INET6) {
            if (sock.remote_ipv6) |dst| {
                ipv6.sendPacket(dst, ipv6.NEXT_HEADER_UDP, kernel_buffer[0..to_send]);
                return @intCast(to_send);
            }
            return abi.ENOTCONN;
        }
        const sent = sock.send(kernel_buffer[0..to_send]) catch |err| return errno.socketErrno(err);
        return @intCast(sent);
    }

    if (sock.address_family == .AF_INET6) {
        const endpoint = parseSockAddrIn6(dest_addr, addr_len) orelse return abi.EINVAL;
        ipv6.sendPacket(endpoint.addr, ipv6.NEXT_HEADER_UDP, kernel_buffer[0..to_send]);
        return @intCast(to_send);
    }

    const endpoint = parseSockAddrIn(dest_addr, addr_len) orelse return abi.EINVAL;
    sock.sendTo(kernel_buffer[0..to_send], endpoint.addr, endpoint.port) catch |err| return errno.socketErrno(err);
    return @intCast(to_send);
}

pub fn sys_recvfrom(sockfd: i32, buf: [*]u8, len: usize, src_addr: usize, addr_len_ptr: usize) i32 {
    const sock = getInetSocket(sockfd) orelse return abi.EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return abi.EINVAL;

    var kernel_buffer: [SOCKET_TRANSFER_BUFFER_SIZE]u8 = undefined;
    const to_recv = @min(len, kernel_buffer.len);

    if (src_addr == 0) {
        const received = sock.recv(kernel_buffer[0..to_recv]) catch |err| return errno.socketErrno(err);
        if (received == 0) return 0;
        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return abi.EINVAL;
        return @intCast(received);
    }

    if (sock.address_family == .AF_INET6) {
        const received = sock.recv(kernel_buffer[0..to_recv]) catch |err| return errno.socketErrno(err);
        if (received == 0) return 0;
        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return abi.EINVAL;
        if (sock.remote_ipv6) |from_ipv6| {
            _ = writeSockAddrIn6(src_addr, addr_len_ptr, .{ .addr = from_ipv6, .port = sock.remote_port });
        }
        return @intCast(received);
    }

    var from_addr = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } };
    var from_port: u16 = 0;
    const received = sock.recvFrom(kernel_buffer[0..to_recv], &from_addr, &from_port) catch |err| return errno.socketErrno(err);
    if (received == 0) return 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return abi.EINVAL;
    _ = writeSockAddrIn(src_addr, addr_len_ptr, .{ .addr = from_addr, .port = from_port });
    return @intCast(received);
}

pub fn sys_getsockname(sockfd: i32, addr_ptr: usize, addr_len_ptr: usize) i32 {
    const sock = getInetSocket(sockfd) orelse return abi.EBADF;
    if (sock.address_family == .AF_INET6) {
        const local = sock.local_ipv6 orelse ipv6.UNSPECIFIED;
        return writeSockAddrIn6(addr_ptr, addr_len_ptr, .{ .addr = local, .port = sock.local_port });
    }
    return writeSockAddrIn(addr_ptr, addr_len_ptr, .{ .addr = sock.local_addr, .port = sock.local_port });
}

pub fn sys_getpeername(sockfd: i32, addr_ptr: usize, addr_len_ptr: usize) i32 {
    const sock = getInetSocket(sockfd) orelse return abi.EBADF;
    if (sock.state != .CONNECTED) return abi.ENOTCONN;
    if (sock.address_family == .AF_INET6) {
        const remote = sock.remote_ipv6 orelse ipv6.UNSPECIFIED;
        return writeSockAddrIn6(addr_ptr, addr_len_ptr, .{ .addr = remote, .port = sock.remote_port });
    }
    return writeSockAddrIn(addr_ptr, addr_len_ptr, .{ .addr = sock.remote_addr, .port = sock.remote_port });
}

pub fn sys_getsockopt(sockfd: i32, level: i32, optname: i32, optval_addr: usize, optlen_addr: usize) i32 {
    const sock = getInetSocket(sockfd) orelse return abi.EBADF;

    if (!protection.verifyUserPointer(optval_addr, @sizeOf(i32))) return abi.EINVAL;

    var val: i32 = 0;

    if (level == SOL_SOCKET) {
        switch (optname) {
            SO_TYPE => val = switch (sock.socket_type) {
                .STREAM => @intCast(SOCK_STREAM),
                .DGRAM => @intCast(SOCK_DGRAM),
                else => 0,
            },
            SO_ERROR => val = 0,
            SO_REUSEADDR, SO_KEEPALIVE, SO_BROADCAST => val = 0,
            SO_SNDBUF => val = @intCast(SOCKET_TRANSFER_BUFFER_SIZE),
            SO_RCVBUF => val = @intCast(SOCKET_TRANSFER_BUFFER_SIZE),
            SO_LINGER => val = 0,
            SO_RCVTIMEO, SO_SNDTIMEO => val = 0,
            else => return abi.ENOPROTOOPT,
        }
    } else if (level == IPPROTO_TCP) {
        switch (optname) {
            TCP_NODELAY => val = 1,
            else => return abi.ENOPROTOOPT,
        }
    } else {
        return abi.ENOPROTOOPT;
    }

    protection.copyToUser(optval_addr, std.mem.asBytes(&val)) catch return abi.EINVAL;
    if (optlen_addr != 0 and protection.verifyUserPointer(optlen_addr, @sizeOf(u32))) {
        var len: u32 = @sizeOf(i32);
        protection.copyToUser(optlen_addr, std.mem.asBytes(&len)) catch {};
    }
    return 0;
}

pub fn sys_setsockopt(sockfd: i32, level: i32, optname: i32, optval_addr: usize, optlen: u32) i32 {
    _ = getInetSocket(sockfd) orelse return abi.EBADF;

    if (optlen < @sizeOf(i32)) return abi.EINVAL;
    if (!protection.verifyUserPointer(optval_addr, @sizeOf(i32))) return abi.EINVAL;

    if (level == SOL_SOCKET) {
        switch (optname) {
            SO_REUSEADDR, SO_KEEPALIVE, SO_BROADCAST => return 0,
            SO_SNDBUF, SO_RCVBUF => return 0,
            SO_LINGER => return 0,
            SO_RCVTIMEO, SO_SNDTIMEO => return 0,
            else => return abi.ENOPROTOOPT,
        }
    } else if (level == IPPROTO_TCP) {
        switch (optname) {
            TCP_NODELAY => return 0,
            else => return abi.ENOPROTOOPT,
        }
    } else {
        return abi.ENOPROTOOPT;
    }
}

pub fn sys_accept4(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, addr: usize, addrlen: usize, flags: u32) i32 {
    _ = addr;
    _ = addrlen;

    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + @as(i32, @intCast(unix_socket_count))) {
        const idx: usize = @intCast(sockfd - unix_socket_fd_base);
        const usock = &unix_sockets[idx];
        if (!usock.in_use or !usock.listening) return abi.EBADF;

        for (0..unix_socket_count) |i| {
            const peer = &unix_sockets[i];
            if (peer.in_use and peer.connected and peer.peer == usock) {
                for (0..unix_socket_count) |j| {
                    const new_sock = &unix_sockets[j];
                    if (!new_sock.in_use) {
                        new_sock.in_use = true;
                        new_sock.connected = true;
                        new_sock.peer = peer;
                        peer.peer = new_sock;
                        const new_fd: i32 = @intCast(@as(i32, @intCast(j)) + unix_socket_fd_base);
                        _ = flags;
                        return new_fd;
                    }
                }
                return abi.EMFILE;
            }
        }
        return abi.EAGAIN;
    }

    const sock_idx = inetSocketIndex(sockfd) orelse return abi.EBADF;
    const sock = socket_table[sock_idx] orelse return abi.EBADF;
    const client = sock.accept() catch |err| return errno.socketErrno(err);

    for (0..socket_table.len) |i| {
        if (socket_table[i] == null) {
            socket_table[i] = client;
            return @intCast(@as(i32, @intCast(i)) + socket_fd_base);
        }
    }

    client.close();
    return abi.EMFILE;
}

pub fn sys_socketpair(unix_sockets: *UnixSocketTable, domain: i32, sock_type: i32, protocol: i32, sv: usize) i32 {
    _ = protocol;
    _ = sock_type;

    if (!protection.verifyUserPointer(sv, @sizeOf([2]i32))) return abi.EFAULT;
    if (domain != @as(i32, @intCast(AF_UNIX))) return abi.EAFNOSUPPORT;

    var fd1: i32 = -1;
    var fd2: i32 = -1;

    for (0..unix_socket_count) |i| {
        const usock = &unix_sockets[i];
        if (!usock.in_use) {
            if (fd1 == -1) {
                usock.in_use = true;
                usock.connected = true;
                fd1 = @intCast(@as(i32, @intCast(i)) + unix_socket_fd_base);
            } else {
                usock.in_use = true;
                usock.connected = true;
                fd2 = @intCast(@as(i32, @intCast(i)) + unix_socket_fd_base);

                const idx1: usize = @intCast(fd1 - unix_socket_fd_base);
                unix_sockets[idx1].peer = usock;
                usock.peer = &unix_sockets[idx1];
                break;
            }
        }
    }

    if (fd1 == -1 or fd2 == -1) {
        if (fd1 != -1) {
            const idx: usize = @intCast(fd1 - unix_socket_fd_base);
            unix_sockets[idx].in_use = false;
            unix_sockets[idx].connected = false;
        }
        return abi.EMFILE;
    }

    const fds = [2]i32{ fd1, fd2 };
    protection.copyToUser(sv, std.mem.asBytes(&fds)) catch {
        const idx1: usize = @intCast(fd1 - unix_socket_fd_base);
        const idx2: usize = @intCast(fd2 - unix_socket_fd_base);
        unix_sockets[idx1].in_use = false;
        unix_sockets[idx1].connected = false;
        unix_sockets[idx1].peer = null;
        unix_sockets[idx2].in_use = false;
        unix_sockets[idx2].connected = false;
        unix_sockets[idx2].peer = null;
        return abi.EFAULT;
    };
    return 0;
}
