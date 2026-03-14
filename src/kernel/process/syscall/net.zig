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
            readiness.notifyAll();
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
        readiness.notifyAll();
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
    readiness.notifyAll();
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
    readiness.notifyAll();
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
                    readiness.notifyAll();
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
        readiness.notifyAll();
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
                        readiness.notifyAll();
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
            readiness.notifyAll();
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
    readiness.notifyAll();
    return 0;
}
