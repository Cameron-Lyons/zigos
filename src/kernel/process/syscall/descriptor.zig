const abi = @import("abi.zig");
const syscall_event = @import("event.zig");
const syscall_net = @import("net.zig");
const syscall_time = @import("time.zig");

pub const DescriptorKind = enum {
    inet_socket,
    unix_socket,
    epoll,
    eventfd,
    signalfd,
    inotify,
    timerfd,
};

pub const Descriptor = struct {
    fd: i32,
    kind: DescriptorKind,
};

pub fn lookup(fd: i32) ?Descriptor {
    if (syscall_net.isInetSocketFd(fd)) {
        return .{ .fd = fd, .kind = .inet_socket };
    }
    if (syscall_net.isUnixSocketFd(fd)) {
        return .{ .fd = fd, .kind = .unix_socket };
    }
    if (syscall_event.isEpollFd(fd)) {
        return .{ .fd = fd, .kind = .epoll };
    }
    if (syscall_event.isEventFd(fd)) {
        return .{ .fd = fd, .kind = .eventfd };
    }
    if (syscall_event.isSignalFd(fd)) {
        return .{ .fd = fd, .kind = .signalfd };
    }
    if (syscall_event.isInotifyFd(fd)) {
        return .{ .fd = fd, .kind = .inotify };
    }
    if (syscall_time.isTimerFd(fd)) {
        return .{ .fd = fd, .kind = .timerfd };
    }
    return null;
}

pub fn isSpecial(fd: i32) bool {
    return lookup(fd) != null;
}

pub fn poll(fd: i32, requested_events: u16) ?error{BadFd}!u16 {
    const descriptor = lookup(fd) orelse return null;

    return switch (descriptor.kind) {
        .inet_socket, .unix_socket => syscall_net.pollSocketFd(fd, requested_events),
        .eventfd, .signalfd, .inotify, .epoll => syscall_event.pollPseudoFd(fd, requested_events).?,
        .timerfd => syscall_time.pollTimerFd(fd, requested_events).?,
    };
}

pub fn read(fd: i32, buffer: []u8) ?i32 {
    const descriptor = lookup(fd) orelse return null;

    return switch (descriptor.kind) {
        .inet_socket, .unix_socket => syscall_net.readSocketFd(fd, buffer) orelse abi.EBADF,
        .eventfd, .signalfd, .inotify, .epoll => syscall_event.readPseudoFd(fd, buffer).?,
        .timerfd => syscall_time.readTimerFd(fd, buffer).?,
    };
}

pub fn write(fd: i32, buffer: []const u8) ?i32 {
    const descriptor = lookup(fd) orelse return null;

    return switch (descriptor.kind) {
        .inet_socket, .unix_socket => syscall_net.writeSocketFd(fd, buffer) orelse abi.EBADF,
        .eventfd, .signalfd, .inotify, .epoll => syscall_event.writePseudoFd(fd, buffer).?,
        .timerfd => abi.EBADF,
    };
}

pub fn waitDeadline(fd: i32) ?u64 {
    const descriptor = lookup(fd) orelse return null;

    return switch (descriptor.kind) {
        .timerfd => syscall_time.nextTimerFdDeadline(fd),
        else => null,
    };
}

pub fn close(unix_sockets: *syscall_net.UnixSocketTable, socket_table: *syscall_net.SocketTable, fd: i32) ?i32 {
    const descriptor = lookup(fd) orelse return null;

    return switch (descriptor.kind) {
        .inet_socket, .unix_socket => syscall_net.closeSocketFd(unix_sockets, socket_table, fd),
        .timerfd => syscall_time.closeTimerFd(fd),
        .epoll, .eventfd, .signalfd, .inotify => syscall_event.closePseudoFd(fd),
    };
}
