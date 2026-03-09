const std = @import("std");
const abi = @import("abi.zig");
const errno = @import("errno.zig");
const ipv4 = @import("../../net/ipv4.zig");
const ipv6 = @import("../../net/ipv6.zig");
const protection = @import("../../memory/protection.zig");
const socket = @import("../../net/socket.zig");

pub const AF_UNIX: u32 = 1;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;

pub const unix_socket_fd_base: i32 = 1000;
pub const unix_socket_count: usize = 64;

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

pub const UnixSocket = struct {
    path: [108]u8,
    path_len: usize,
    peer: ?*UnixSocket,
    recv_buffer: [4096]u8,
    recv_head: usize,
    recv_tail: usize,
    recv_count: usize,
    listening: bool,
    connected: bool,
    in_use: bool,
};

pub const SocketTable = [64]?*socket.Socket;
pub const UnixSocketTable = [unix_socket_count]UnixSocket;

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
            return @intCast(i);
        }
    }

    sock.close();
    return abi.EMFILE;
}

pub fn sys_bind(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + unix_socket_count) {
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

    if (sockfd < 0 or sockfd >= socket_table.len) return abi.EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return abi.EBADF;

    if (sock.address_family == .AF_INET6) {
        if (addr_len < @sizeOf(SockAddrIn6)) return abi.EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return abi.EINVAL;

        var addr_buf: [@sizeOf(SockAddrIn6)]u8 = undefined;
        protection.copyFromUser(&addr_buf, addr_ptr) catch return abi.EINVAL;
        const addr: *const SockAddrIn6 = @ptrCast(@alignCast(&addr_buf));

        sock.local_ipv6 = ipv6.IPv6Address{ .octets = addr.addr };
        sock.local_port = @byteSwap(addr.port);
        return 0;
    }

    if (addr_len < @sizeOf(SockAddrIn)) return abi.EINVAL;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return abi.EINVAL;

    var addr_buf: [@sizeOf(SockAddrIn)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return abi.EINVAL;
    const addr: *const SockAddrIn = @ptrCast(@alignCast(&addr_buf));

    const ipv4_addr = ipv4.IPv4Address{
        .octets = .{
            @intCast((addr.addr >> 0) & 0xFF),
            @intCast((addr.addr >> 8) & 0xFF),
            @intCast((addr.addr >> 16) & 0xFF),
            @intCast((addr.addr >> 24) & 0xFF),
        },
    };

    sock.bind(ipv4_addr, @byteSwap(addr.port)) catch |err| return errno.socketErrno(err);
    return 0;
}

pub fn sys_connect(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + unix_socket_count) {
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
                    return 0;
                }
            }
        }
        return abi.ECONNREFUSED;
    }

    if (sockfd < 0 or sockfd >= socket_table.len) return abi.EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return abi.EBADF;

    if (sock.address_family == .AF_INET6) {
        if (addr_len < @sizeOf(SockAddrIn6)) return abi.EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return abi.EINVAL;

        var addr_buf: [@sizeOf(SockAddrIn6)]u8 = undefined;
        protection.copyFromUser(&addr_buf, addr_ptr) catch return abi.EINVAL;
        const addr: *const SockAddrIn6 = @ptrCast(@alignCast(&addr_buf));

        sock.remote_ipv6 = ipv6.IPv6Address{ .octets = addr.addr };
        sock.remote_port = @byteSwap(addr.port);
        sock.state = .CONNECTED;
        return 0;
    }

    if (addr_len < @sizeOf(SockAddrIn)) return abi.EINVAL;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return abi.EINVAL;

    var addr_buf: [@sizeOf(SockAddrIn)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return abi.EINVAL;
    const addr: *const SockAddrIn = @ptrCast(@alignCast(&addr_buf));

    const ipv4_addr = ipv4.IPv4Address{
        .octets = .{
            @intCast((addr.addr >> 0) & 0xFF),
            @intCast((addr.addr >> 8) & 0xFF),
            @intCast((addr.addr >> 16) & 0xFF),
            @intCast((addr.addr >> 24) & 0xFF),
        },
    };

    sock.connect(ipv4_addr, @byteSwap(addr.port)) catch |err| return errno.socketErrno(err);
    return 0;
}

pub fn sys_listen(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, backlog: u32) i32 {
    _ = backlog;
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + unix_socket_count) {
        const idx: usize = @intCast(sockfd - unix_socket_fd_base);
        const usock = &unix_sockets[idx];
        if (!usock.in_use) return abi.EBADF;
        usock.listening = true;
        return 0;
    }

    if (sockfd < 0 or sockfd >= socket_table.len) return abi.EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return abi.EBADF;
    sock.listen(5) catch |err| return errno.socketErrno(err);
    return 0;
}

pub fn sys_accept(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32) i32 {
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + unix_socket_count) {
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
                        return @intCast(@as(i32, @intCast(j)) + unix_socket_fd_base);
                    }
                }
                return abi.EMFILE;
            }
        }
        return abi.EAGAIN;
    }

    if (sockfd < 0 or sockfd >= socket_table.len) return abi.EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return abi.EBADF;

    const client = sock.accept() catch |err| return errno.socketErrno(err);

    for (0..socket_table.len) |i| {
        if (socket_table[i] == null) {
            socket_table[i] = client;
            return @intCast(i);
        }
    }

    client.close();
    return abi.EMFILE;
}

pub fn sys_send(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, buf: [*]const u8, len: usize) i32 {
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + unix_socket_count) {
        const idx: usize = @intCast(sockfd - unix_socket_fd_base);
        const usock = &unix_sockets[idx];
        if (!usock.in_use or !usock.connected) return abi.EBADF;

        const peer = usock.peer orelse return abi.ENOTCONN;
        if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return abi.EINVAL;

        var kernel_buffer: [4096]u8 = undefined;
        const to_send = @min(len, kernel_buffer.len);
        protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return abi.EINVAL;

        const available = peer.recv_buffer.len - peer.recv_count;
        const copy_len = @min(to_send, available);
        if (copy_len == 0) return abi.EAGAIN;

        for (0..copy_len) |i| {
            peer.recv_buffer[peer.recv_tail] = kernel_buffer[i];
            peer.recv_tail = (peer.recv_tail + 1) % peer.recv_buffer.len;
        }
        peer.recv_count += copy_len;
        return @intCast(copy_len);
    }

    if (sockfd < 0 or sockfd >= socket_table.len) return abi.EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return abi.EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return abi.EINVAL;

    var kernel_buffer: [4096]u8 = undefined;
    const to_send = @min(len, kernel_buffer.len);
    protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return abi.EINVAL;

    const sent = sock.send(kernel_buffer[0..to_send]) catch |err| return errno.socketErrno(err);
    return @intCast(sent);
}

pub fn sys_recv(unix_sockets: *UnixSocketTable, socket_table: *SocketTable, sockfd: i32, buf: [*]u8, len: usize) i32 {
    if (sockfd >= unix_socket_fd_base and sockfd < unix_socket_fd_base + unix_socket_count) {
        const idx: usize = @intCast(sockfd - unix_socket_fd_base);
        const usock = &unix_sockets[idx];
        if (!usock.in_use) return abi.EBADF;

        if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return abi.EINVAL;
        if (usock.recv_count == 0) return 0;

        var kernel_buffer: [4096]u8 = undefined;
        const to_recv = @min(len, @min(usock.recv_count, kernel_buffer.len));

        for (0..to_recv) |i| {
            kernel_buffer[i] = usock.recv_buffer[usock.recv_head];
            usock.recv_head = (usock.recv_head + 1) % usock.recv_buffer.len;
        }
        usock.recv_count -= to_recv;

        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..to_recv]) catch return abi.EINVAL;
        return @intCast(to_recv);
    }

    if (sockfd < 0 or sockfd >= socket_table.len) return abi.EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return abi.EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return abi.EINVAL;

    var kernel_buffer: [4096]u8 = undefined;
    const to_recv = @min(len, kernel_buffer.len);

    const received = sock.recv(kernel_buffer[0..to_recv]) catch |err| return errno.socketErrno(err);
    if (received == 0) return 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return abi.EINVAL;
    return @intCast(received);
}

pub fn sys_shutdown(socket_table: *SocketTable, sockfd: i32) i32 {
    if (sockfd < 0 or sockfd >= socket_table.len) return abi.EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return abi.EBADF;
    sock.close();
    socket_table[@intCast(sockfd)] = null;
    return 0;
}
