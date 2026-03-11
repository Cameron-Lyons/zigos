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

pub const Observation = struct {
    revents: u16,
    invalid: bool,
    deadline: ?u64,
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

pub fn observe(fd: i32, requested_events: u16, track_deadline: bool) ?Observation {
    const known = lookup(fd) orelse return null;
    const deadline = if (track_deadline) waitDeadlineKnown(known) else null;
    const revents = pollKnown(known, requested_events) catch {
        return .{
            .revents = 0,
            .invalid = true,
            .deadline = deadline,
        };
    };

    return .{
        .revents = revents,
        .invalid = false,
        .deadline = deadline,
    };
}

pub fn poll(fd: i32, requested_events: u16) ?error{BadFd}!u16 {
    const known = lookup(fd) orelse return null;
    return pollKnown(known, requested_events);
}

pub fn read(fd: i32, buffer: []u8) ?i32 {
    const known = lookup(fd) orelse return null;
    return readKnown(known, buffer);
}

pub fn write(fd: i32, buffer: []const u8) ?i32 {
    const known = lookup(fd) orelse return null;
    return writeKnown(known, buffer);
}

pub fn waitDeadline(fd: i32) ?u64 {
    const known = lookup(fd) orelse return null;
    return waitDeadlineKnown(known);
}

pub fn close(unix_sockets: *syscall_net.UnixSocketTable, socket_table: *syscall_net.SocketTable, fd: i32) ?i32 {
    const known = lookup(fd) orelse return null;
    return closeKnown(known, unix_sockets, socket_table);
}

fn pollKnown(known: Descriptor, requested_events: u16) error{BadFd}!u16 {
    return switch (known.kind) {
        .inet_socket, .unix_socket => syscall_net.pollSocketFd(known.fd, requested_events),
        .eventfd, .signalfd, .inotify, .epoll => syscall_event.pollPseudoFd(known.fd, requested_events).?,
        .timerfd => syscall_time.pollTimerFd(known.fd, requested_events).?,
    };
}

fn readKnown(known: Descriptor, buffer: []u8) i32 {
    return switch (known.kind) {
        .inet_socket, .unix_socket => syscall_net.readSocketFd(known.fd, buffer) orelse abi.EBADF,
        .eventfd, .signalfd, .inotify, .epoll => syscall_event.readPseudoFd(known.fd, buffer).?,
        .timerfd => syscall_time.readTimerFd(known.fd, buffer).?,
    };
}

fn writeKnown(known: Descriptor, buffer: []const u8) i32 {
    return switch (known.kind) {
        .inet_socket, .unix_socket => syscall_net.writeSocketFd(known.fd, buffer) orelse abi.EBADF,
        .eventfd, .signalfd, .inotify, .epoll => syscall_event.writePseudoFd(known.fd, buffer).?,
        .timerfd => abi.EBADF,
    };
}

fn waitDeadlineKnown(known: Descriptor) ?u64 {
    return switch (known.kind) {
        .timerfd => syscall_time.nextTimerFdDeadline(known.fd),
        else => null,
    };
}

fn closeKnown(known: Descriptor, unix_sockets: *syscall_net.UnixSocketTable, socket_table: *syscall_net.SocketTable) i32 {
    return switch (known.kind) {
        .inet_socket, .unix_socket => syscall_net.closeSocketFd(unix_sockets, socket_table, known.fd).?,
        .timerfd => syscall_time.closeTimerFd(known.fd),
        .epoll, .eventfd, .signalfd, .inotify => syscall_event.closePseudoFd(known.fd).?,
    };
}
