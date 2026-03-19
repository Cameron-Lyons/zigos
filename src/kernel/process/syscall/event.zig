const std = @import("std");
const abi = @import("abi.zig");
const common = @import("common.zig");
const descriptor = @import("descriptor.zig");
const kernel_signal = @import("../signal.zig");
const readiness = @import("readiness.zig");
const syscall_time = @import("time.zig");
const protection = @import("../../memory/protection.zig");
const timer = @import("../../timer/timer.zig");
const vfs = @import("../../fs/vfs.zig");

const MAX_SELECT_FDS = 1024;
const FD_SET_WORD_BITS = @bitSizeOf(u32);
const FD_SET_WORD_COUNT: usize = MAX_SELECT_FDS / FD_SET_WORD_BITS;
const MAX_POLL_FDS: usize = 256;
const EPOLL_INSTANCE_COUNT: usize = 64;
const EPOLL_ENTRY_CAPACITY: usize = 64;
const EVENTFD_COUNT: usize = 64;
const SIGNALFD_COUNT: usize = 64;
const SIGNALFD_MASK_WORD_BITS = @bitSizeOf(u32);
const INOTIFY_NAME_BUFFER_SIZE: usize = 128;
const INOTIFY_NAME_ALIGNMENT: usize = @sizeOf(u32);
const INOTIFY_WATCH_CAPACITY: usize = 16;
const INOTIFY_QUEUE_CAPACITY: usize = 32;
const INOTIFY_INSTANCE_COUNT: usize = 32;
const MILLISECONDS_PER_SECOND: u64 = 1000;
const NANOSECONDS_PER_MILLISECOND: u64 = 1_000_000;
const NANOSECONDS_PER_MICROSECOND: i32 = 1_000;
const MAX_TIMEOUT_MS: u64 = std.math.maxInt(i32);

const FdSet = extern struct {
    fds_bits: [FD_SET_WORD_COUNT]u32,
};

const Timeval = extern struct {
    tv_sec: i32,
    tv_usec: i32,
};

const PollFd = extern struct {
    fd: i32,
    events: i16,
    revents: i16,
};

const EpollEvent = extern struct {
    events: u32,
    data: u64,
};

const EpollEntry = struct {
    fd: i32,
    events: u32,
    data: u64,
};

const EpollInstance = struct {
    entries: [EPOLL_ENTRY_CAPACITY]?EpollEntry,
    count: usize,
    in_use: bool,
};

const EventFd = struct {
    counter: u64,
    flags: u32,
    in_use: bool,
};

const SignalFd = struct {
    mask: u64,
    flags: u32,
    in_use: bool,
};

pub const SignalFdInfo = extern struct {
    signo: i32,
    errno: i32,
    code: i32,
    pid: i32,
    uid: u32,
    status: i32,
};

pub const InotifyEventHeader = extern struct {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
};

const InotifyQueuedEvent = struct {
    wd: i32,
    mask: u32,
    cookie: u32,
    name_len: usize,
    name: [INOTIFY_NAME_BUFFER_SIZE]u8,
};

const InotifyWatch = struct {
    wd: i32,
    pathname: [common.USER_PATH_BUFFER_SIZE]u8,
    path_len: usize,
    mask: u32,
    in_use: bool,
};

const InotifyInstance = struct {
    watches: [INOTIFY_WATCH_CAPACITY]InotifyWatch,
    queue: [INOTIFY_QUEUE_CAPACITY]InotifyQueuedEvent,
    head: u8,
    tail: u8,
    flags: u32,
    in_use: bool,
};

const POLLIN: i16 = 0x001;
const POLLOUT: i16 = 0x004;
const POLLNVAL: i16 = 0x020;
const VFS_POLLIN: u16 = 0x001;
const VFS_POLLOUT: u16 = 0x004;
const EVENTFD_MAX_COUNTER = std.math.maxInt(u64) - 1;

const EPOLL_BASE: i32 = abi.FD_OFFSET + 200;
const EPOLL_LIMIT: i32 = EPOLL_BASE + @as(i32, @intCast(EPOLL_INSTANCE_COUNT));
const EVENTFD_BASE: i32 = 2000;
const EVENTFD_LIMIT: i32 = EVENTFD_BASE + @as(i32, @intCast(EVENTFD_COUNT));
const SIGNALFD_BASE: i32 = 3000;
const SIGNALFD_LIMIT: i32 = SIGNALFD_BASE + @as(i32, @intCast(SIGNALFD_COUNT));
const INOTIFY_BASE: i32 = 4000;
const INOTIFY_LIMIT: i32 = INOTIFY_BASE + @as(i32, @intCast(INOTIFY_INSTANCE_COUNT));

var epoll_instances: [EPOLL_INSTANCE_COUNT]EpollInstance = [_]EpollInstance{.{
    .entries = [_]?EpollEntry{null} ** EPOLL_ENTRY_CAPACITY,
    .count = 0,
    .in_use = false,
}} ** EPOLL_INSTANCE_COUNT;

var eventfd_table: [EVENTFD_COUNT]EventFd = [_]EventFd{.{ .counter = 0, .flags = 0, .in_use = false }} ** EVENTFD_COUNT;
var signalfd_table: [SIGNALFD_COUNT]SignalFd = [_]SignalFd{.{ .mask = 0, .flags = 0, .in_use = false }} ** SIGNALFD_COUNT;

var inotify_instances: [INOTIFY_INSTANCE_COUNT]InotifyInstance = [_]InotifyInstance{.{
    .watches = [_]InotifyWatch{.{
        .wd = -1,
        .pathname = [_]u8{0} ** common.USER_PATH_BUFFER_SIZE,
        .path_len = 0,
        .mask = 0,
        .in_use = false,
    }} ** INOTIFY_WATCH_CAPACITY,
    .queue = [_]InotifyQueuedEvent{.{
        .wd = -1,
        .mask = 0,
        .cookie = 0,
        .name_len = 0,
        .name = [_]u8{0} ** INOTIFY_NAME_BUFFER_SIZE,
    }} ** INOTIFY_QUEUE_CAPACITY,
    .head = 0,
    .tail = 0,
    .flags = 0,
    .in_use = false,
}} ** INOTIFY_INSTANCE_COUNT;

var next_inotify_wd: i32 = 1;
var next_inotify_cookie: u32 = 1;

pub fn init() void {
    for (&epoll_instances) |*inst| {
        inst.* = .{
            .entries = [_]?EpollEntry{null} ** EPOLL_ENTRY_CAPACITY,
            .count = 0,
            .in_use = false,
        };
    }

    for (&eventfd_table) |*efd| {
        efd.* = .{ .counter = 0, .flags = 0, .in_use = false };
    }

    for (&signalfd_table) |*sfd| {
        sfd.* = .{ .mask = 0, .flags = 0, .in_use = false };
    }

    for (&inotify_instances) |*inst| {
        inst.* = .{
            .watches = [_]InotifyWatch{.{
                .wd = -1,
                .pathname = [_]u8{0} ** common.USER_PATH_BUFFER_SIZE,
                .path_len = 0,
                .mask = 0,
                .in_use = false,
            }} ** INOTIFY_WATCH_CAPACITY,
            .queue = [_]InotifyQueuedEvent{.{
                .wd = -1,
                .mask = 0,
                .cookie = 0,
                .name_len = 0,
                .name = [_]u8{0} ** INOTIFY_NAME_BUFFER_SIZE,
            }} ** INOTIFY_QUEUE_CAPACITY,
            .head = 0,
            .tail = 0,
            .flags = 0,
            .in_use = false,
        };
    }

    next_inotify_wd = 1;
    next_inotify_cookie = 1;
}

const ReadyScan = struct {
    count: i32,
    earliest_deadline: ?u64,
    wait_mask: u32,
};

const EpollScan = struct {
    count: usize,
    earliest_deadline: ?u64,
    wait_mask: u32,
};

const FdObservation = struct {
    revents: u16,
    invalid: bool,
    deadline: ?u64,
};

pub fn closePseudoFd(fd: i32) ?i32 {
    if (isEventFd(fd)) {
        const idx: usize = @intCast(fd - EVENTFD_BASE);
        var efd = &eventfd_table[idx];
        if (!efd.in_use) return abi.EBADF;
        efd.in_use = false;
        readiness.notifyPseudo();
        return 0;
    }

    if (isSignalFd(fd)) {
        const idx: usize = @intCast(fd - SIGNALFD_BASE);
        var sfd = &signalfd_table[idx];
        if (!sfd.in_use) return abi.EBADF;
        sfd.in_use = false;
        readiness.notifyPseudo();
        return 0;
    }

    if (isInotifyFd(fd)) {
        const idx: usize = @intCast(fd - INOTIFY_BASE);
        const inst = &inotify_instances[idx];
        if (!inst.in_use) return abi.EBADF;
        resetInotifyInstance(inst);
        readiness.notifyPseudo();
        return 0;
    }

    if (isEpollFd(fd)) {
        const idx: usize = @intCast(fd - EPOLL_BASE);
        var inst = &epoll_instances[idx];
        if (!inst.in_use) return abi.EBADF;
        inst.in_use = false;
        inst.count = 0;
        readiness.notifyPseudo();
        return 0;
    }

    return null;
}

pub fn pollPseudoFd(fd: i32, requested_events: u16) ?error{BadFd}!u16 {
    if (isEventFd(fd)) {
        return pollEventFd(fd, requested_events);
    }

    if (isSignalFd(fd)) {
        return pollSignalFd(fd, requested_events);
    }

    if (isInotifyFd(fd)) {
        return pollInotifyFd(fd, requested_events);
    }

    if (isEpollFd(fd)) {
        return error.BadFd;
    }

    return null;
}

pub fn readPseudoFd(fd: i32, buffer: []u8) ?i32 {
    if (isEventFd(fd)) {
        return readEventFd(fd, buffer);
    }

    if (isSignalFd(fd)) {
        return readSignalFd(fd, buffer);
    }

    if (isInotifyFd(fd)) {
        return readInotifyFd(fd, buffer);
    }

    if (isEpollFd(fd)) {
        return abi.EBADF;
    }

    return null;
}

pub fn writePseudoFd(fd: i32, buffer: []const u8) ?i32 {
    if (isEventFd(fd)) {
        return writeEventFd(fd, buffer);
    }

    if (isSignalFd(fd) or isInotifyFd(fd) or isEpollFd(fd)) {
        return abi.EBADF;
    }

    return null;
}

pub fn isEpollFd(fd: i32) bool {
    return fd >= EPOLL_BASE and fd < EPOLL_LIMIT;
}

pub fn sys_select(nfds: i32, readfds_addr: usize, writefds_addr: usize, exceptfds_addr: usize, timeout_addr: usize) i32 {
    if (nfds < 0 or nfds > MAX_SELECT_FDS) return abi.EINVAL;

    var readfds: FdSet = std.mem.zeroes(FdSet);
    var writefds: FdSet = std.mem.zeroes(FdSet);
    var exceptfds: FdSet = std.mem.zeroes(FdSet);
    var result_readfds: FdSet = std.mem.zeroes(FdSet);
    var result_writefds: FdSet = std.mem.zeroes(FdSet);
    var result_exceptfds: FdSet = std.mem.zeroes(FdSet);

    if (readfds_addr != 0) {
        if (!protection.verifyUserPointer(readfds_addr, @sizeOf(FdSet))) return abi.EINVAL;
        protection.copyFromUser(std.mem.asBytes(&readfds), readfds_addr) catch return abi.EINVAL;
    }

    if (writefds_addr != 0) {
        if (!protection.verifyUserPointer(writefds_addr, @sizeOf(FdSet))) return abi.EINVAL;
        protection.copyFromUser(std.mem.asBytes(&writefds), writefds_addr) catch return abi.EINVAL;
    }

    if (exceptfds_addr != 0) {
        if (!protection.verifyUserPointer(exceptfds_addr, @sizeOf(FdSet))) return abi.EINVAL;
        protection.copyFromUser(std.mem.asBytes(&exceptfds), exceptfds_addr) catch return abi.EINVAL;
    }

    var timeout_ms: i64 = -1;
    if (timeout_addr != 0) {
        if (!protection.verifyUserPointer(timeout_addr, @sizeOf(Timeval))) return abi.EINVAL;
        var tv: Timeval = undefined;
        protection.copyFromUser(std.mem.asBytes(&tv), timeout_addr) catch return abi.EINVAL;
        timeout_ms = @as(i64, tv.tv_sec) * 1000 + @divTrunc(tv.tv_usec, 1000);
    }

    var select_scan = selectCheckFds(@intCast(nfds), &readfds, &writefds, &exceptfds, &result_readfds, &result_writefds, &result_exceptfds, false);
    var count = select_scan.count;

    if (timeout_ms == 0 or count > 0) {
        if (readfds_addr != 0) {
            protection.copyToUser(readfds_addr, std.mem.asBytes(&result_readfds)) catch return abi.EINVAL;
        }
        if (writefds_addr != 0) {
            protection.copyToUser(writefds_addr, std.mem.asBytes(&result_writefds)) catch return abi.EINVAL;
        }
        if (exceptfds_addr != 0) {
            protection.copyToUser(exceptfds_addr, std.mem.asBytes(&result_exceptfds)) catch return abi.EINVAL;
        }
        return count;
    }

    const deadline_tick = timeoutDeadline(timeout_ms);

    while (count == 0) {
        const observed_generation = readiness.snapshot();
        select_scan = selectCheckFds(@intCast(nfds), &readfds, &writefds, &exceptfds, &result_readfds, &result_writefds, &result_exceptfds, true);
        count = select_scan.count;
        if (count > 0) break;

        if (deadlineReached(deadline_tick)) break;

        const wait_deadline = earliestDeadline(deadline_tick, select_scan.earliest_deadline);
        _ = readiness.waitForChange(observed_generation, select_scan.wait_mask, wait_deadline);
    }

    if (readfds_addr != 0) {
        protection.copyToUser(readfds_addr, std.mem.asBytes(&result_readfds)) catch return abi.EINVAL;
    }
    if (writefds_addr != 0) {
        protection.copyToUser(writefds_addr, std.mem.asBytes(&result_writefds)) catch return abi.EINVAL;
    }
    if (exceptfds_addr != 0) {
        protection.copyToUser(exceptfds_addr, std.mem.asBytes(&result_exceptfds)) catch return abi.EINVAL;
    }

    return count;
}

pub fn sys_poll(fds_addr: usize, nfds: u32, timeout: i32) i32 {
    if (nfds == 0) return 0;
    if (nfds > @as(u32, @intCast(MAX_POLL_FDS))) return abi.EINVAL;

    const poll_fd_count: usize = @intCast(nfds);
    const copy_size = poll_fd_count * @sizeOf(PollFd);
    if (!protection.verifyUserPointer(fds_addr, copy_size)) return abi.EINVAL;

    var kernel_fds: [MAX_POLL_FDS]PollFd = undefined;
    protection.copyFromUser(std.mem.asBytes(&kernel_fds)[0..copy_size], fds_addr) catch return abi.EINVAL;

    var poll_scan = pollCheckFds(kernel_fds[0..poll_fd_count], false);
    var count = poll_scan.count;

    if (timeout == 0 or count > 0) {
        protection.copyToUser(fds_addr, std.mem.asBytes(&kernel_fds)[0..copy_size]) catch return abi.EINVAL;
        return count;
    }

    const deadline_tick = timeoutDeadline(timeout);

    while (count == 0) {
        const observed_generation = readiness.snapshot();
        poll_scan = pollCheckFds(kernel_fds[0..poll_fd_count], true);
        count = poll_scan.count;
        if (count > 0) break;

        if (deadlineReached(deadline_tick)) break;

        const wait_deadline = earliestDeadline(deadline_tick, poll_scan.earliest_deadline);
        _ = readiness.waitForChange(observed_generation, poll_scan.wait_mask, wait_deadline);
    }

    protection.copyToUser(fds_addr, std.mem.asBytes(&kernel_fds)[0..copy_size]) catch return abi.EINVAL;
    return count;
}

pub fn sys_epoll_create(size: i32) i32 {
    _ = size;

    for (&epoll_instances, 0..) |*inst, i| {
        if (!inst.in_use) {
            inst.in_use = true;
            inst.count = 0;
            for (&inst.entries) |*entry| {
                entry.* = null;
            }
            return @intCast(@as(i32, @intCast(i)) + EPOLL_BASE);
        }
    }
    return abi.EMFILE;
}

pub fn sys_epoll_ctl(epfd: i32, op: u32, fd: i32, event_addr: usize) i32 {
    const idx = epfd - EPOLL_BASE;
    if (idx < 0 or idx >= @as(i32, @intCast(EPOLL_INSTANCE_COUNT))) return abi.EBADF;
    const inst = &epoll_instances[@intCast(idx)];
    if (!inst.in_use) return abi.EBADF;

    switch (op) {
        abi.EPOLL_CTL_ADD => {
            if (event_addr == 0) return abi.EINVAL;
            if (!protection.verifyUserPointer(event_addr, @sizeOf(EpollEvent))) return abi.EINVAL;
            var ev: EpollEvent = undefined;
            protection.copyFromUser(std.mem.asBytes(&ev), event_addr) catch return abi.EINVAL;

            for (inst.entries) |maybe_entry| {
                if (maybe_entry) |entry| {
                    if (entry.fd == fd) return abi.EEXIST;
                }
            }

            for (&inst.entries) |*entry| {
                if (entry.* == null) {
                    entry.* = EpollEntry{ .fd = fd, .events = ev.events, .data = ev.data };
                    inst.count += 1;
                    return 0;
                }
            }
            return abi.ENOSPC;
        },
        abi.EPOLL_CTL_DEL => {
            for (&inst.entries) |*entry| {
                if (entry.*) |current| {
                    if (current.fd == fd) {
                        entry.* = null;
                        inst.count -= 1;
                        return 0;
                    }
                }
            }
            return abi.ENOENT;
        },
        abi.EPOLL_CTL_MOD => {
            if (event_addr == 0) return abi.EINVAL;
            if (!protection.verifyUserPointer(event_addr, @sizeOf(EpollEvent))) return abi.EINVAL;
            var ev: EpollEvent = undefined;
            protection.copyFromUser(std.mem.asBytes(&ev), event_addr) catch return abi.EINVAL;

            for (&inst.entries) |*entry| {
                if (entry.*) |*current| {
                    if (current.fd == fd) {
                        current.events = ev.events;
                        current.data = ev.data;
                        return 0;
                    }
                }
            }
            return abi.ENOENT;
        },
        else => return abi.EINVAL,
    }
}

pub fn sys_epoll_wait(epfd: i32, events_addr: usize, maxevents: i32, timeout: i32) i32 {
    const idx = epfd - EPOLL_BASE;
    if (idx < 0 or idx >= @as(i32, @intCast(EPOLL_INSTANCE_COUNT))) return abi.EBADF;
    const inst = &epoll_instances[@intCast(idx)];
    if (!inst.in_use) return abi.EBADF;

    if (maxevents <= 0) return abi.EINVAL;
    const max: usize = @intCast(maxevents);
    if (!protection.verifyUserPointer(events_addr, max * @sizeOf(EpollEvent))) return abi.EINVAL;

    var events: [EPOLL_ENTRY_CAPACITY]EpollEvent = undefined;

    var epoll_scan = collectEpollEvents(inst, max, &events, false);
    var count = epoll_scan.count;
    if (timeout != 0 and count == 0) {
        const deadline_tick = timeoutDeadline(timeout);

        while (count == 0) {
            const observed_generation = readiness.snapshot();
            epoll_scan = collectEpollEvents(inst, max, &events, true);
            count = epoll_scan.count;
            if (count > 0) break;

            if (deadlineReached(deadline_tick)) break;

            const wait_deadline = earliestDeadline(deadline_tick, epoll_scan.earliest_deadline);
            _ = readiness.waitForChange(observed_generation, epoll_scan.wait_mask, wait_deadline);
        }
    }

    if (count > 0) {
        protection.copyToUser(events_addr, std.mem.sliceAsBytes(events[0..count])) catch return abi.EINVAL;
    }
    return @intCast(count);
}

pub fn sys_eventfd(initval: u32) i32 {
    return sys_eventfd2(initval, 0);
}

pub fn sys_eventfd2(initval: u32, flags: u32) i32 {
    for (&eventfd_table, 0..) |*efd, i| {
        if (!efd.in_use) {
            efd.in_use = true;
            efd.counter = initval;
            efd.flags = flags;
            readiness.notifyPseudo();
            return @intCast(@as(i32, @intCast(i)) + EVENTFD_BASE);
        }
    }
    return abi.EMFILE;
}

pub fn sys_signalfd(fd: i32, mask_ptr: usize, sizemask: usize) i32 {
    return sys_signalfd4(fd, mask_ptr, sizemask, 0);
}

pub fn sys_signalfd4(fd: i32, mask_ptr: usize, sizemask: usize, flags: u32) i32 {
    _ = sizemask;

    if (!protection.verifyUserPointer(mask_ptr, @sizeOf(u64))) return abi.EFAULT;

    var mask: u64 = 0;
    protection.copyFromUser(std.mem.asBytes(&mask), mask_ptr) catch return abi.EFAULT;

    if (fd == -1) {
        for (&signalfd_table, 0..) |*sfd, i| {
            if (!sfd.in_use) {
                sfd.in_use = true;
                sfd.mask = mask;
                sfd.flags = flags;
                readiness.notifyPseudo();
                return @intCast(@as(i32, @intCast(i)) + SIGNALFD_BASE);
            }
        }
        return abi.EMFILE;
    }

    if (isSignalFd(fd)) {
        const idx: usize = @intCast(fd - SIGNALFD_BASE);
        if (!signalfd_table[idx].in_use) return abi.EBADF;
        signalfd_table[idx].mask = mask;
        signalfd_table[idx].flags = flags;
        readiness.notifyPseudo();
        return fd;
    }

    return abi.EBADF;
}

pub fn sys_ppoll(fds_ptr: usize, nfds: u32, timeout_ptr: usize, sigmask_ptr: usize) i32 {
    _ = sigmask_ptr;

    var timeout_ms: i32 = -1;
    if (timeout_ptr != 0) {
        if (!protection.verifyUserPointer(timeout_ptr, @sizeOf(syscall_time.TimeSpec))) return abi.EFAULT;
        var ts: syscall_time.TimeSpec = undefined;
        protection.copyFromUser(std.mem.asBytes(&ts), timeout_ptr) catch return abi.EFAULT;
        if (ts.tv_sec < 0) return abi.EINVAL;
        timeout_ms = timeSpecToTimeoutMilliseconds(ts);
    }

    return sys_poll(fds_ptr, nfds, timeout_ms);
}

pub fn sys_pselect6(nfds: i32, readfds: usize, writefds: usize, exceptfds: usize, timeout_ptr: usize, sigmask_ptr: usize) i32 {
    _ = sigmask_ptr;

    var timeout_arg: usize = 0;
    var timeout_timeval: Timeval = undefined;

    if (timeout_ptr != 0) {
        if (!protection.verifyUserPointer(timeout_ptr, @sizeOf(syscall_time.TimeSpec))) return abi.EFAULT;
        var ts: syscall_time.TimeSpec = undefined;
        protection.copyFromUser(std.mem.asBytes(&ts), timeout_ptr) catch return abi.EFAULT;
        if (ts.tv_sec < 0) return abi.EINVAL;

        timeout_timeval = timeSpecToTimeval(ts);
        timeout_arg = @intFromPtr(&timeout_timeval);
    }

    return sys_select(nfds, readfds, writefds, exceptfds, timeout_arg);
}

pub fn sys_inotify_init() i32 {
    return sys_inotify_init1(0);
}

pub fn sys_inotify_init1(flags: u32) i32 {
    vfs.registerInotifyNotifier(notifyInotifyPathEvent);

    for (&inotify_instances, 0..) |*inst, i| {
        if (!inst.in_use) {
            inst.in_use = true;
            inst.flags = flags;
            for (&inst.watches) |*watch| {
                watch.in_use = false;
                watch.wd = -1;
            }
            inst.head = 0;
            inst.tail = 0;
            readiness.notifyPseudo();
            return @intCast(@as(i32, @intCast(i)) + INOTIFY_BASE);
        }
    }
    return abi.EMFILE;
}

pub fn sys_inotify_add_watch(fd: i32, pathname: [*]const u8, mask: u32) i32 {
    if (!isInotifyFd(fd)) return abi.EBADF;
    const idx: usize = @intCast(fd - INOTIFY_BASE);
    if (!inotify_instances[idx].in_use) return abi.EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), common.USER_PATH_BUFFER_SIZE)) return abi.EFAULT;

    var path_buffer: [common.USER_PATH_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return abi.EFAULT;

    for (&inotify_instances[idx].watches) |*watch| {
        if (!watch.in_use) {
            watch.in_use = true;
            watch.wd = next_inotify_wd;
            next_inotify_wd += 1;
            @memset(&watch.pathname, 0);
            @memcpy(watch.pathname[0..path_slice.len], path_slice);
            watch.path_len = path_slice.len;
            watch.mask = mask;
            return watch.wd;
        }
    }
    return abi.ENOSPC;
}

pub fn sys_inotify_rm_watch(fd: i32, wd: i32) i32 {
    if (!isInotifyFd(fd)) return abi.EBADF;
    const idx: usize = @intCast(fd - INOTIFY_BASE);
    if (!inotify_instances[idx].in_use) return abi.EBADF;

    for (&inotify_instances[idx].watches) |*watch| {
        if (watch.in_use and watch.wd == wd) {
            watch.in_use = false;
            watch.wd = -1;
            return 0;
        }
    }
    return abi.EINVAL;
}

pub fn isEventFd(fd: i32) bool {
    return fd >= EVENTFD_BASE and fd < EVENTFD_LIMIT;
}

pub fn isSignalFd(fd: i32) bool {
    return fd >= SIGNALFD_BASE and fd < SIGNALFD_LIMIT;
}

pub fn isInotifyFd(fd: i32) bool {
    return fd >= INOTIFY_BASE and fd < INOTIFY_LIMIT;
}

fn pollEventFd(fd: i32, requested_events: u16) error{BadFd}!u16 {
    const efd = getEventFd(fd) orelse return error.BadFd;
    var ready: u16 = 0;

    if ((requested_events & VFS_POLLIN) != 0 and efd.counter != 0) {
        ready |= VFS_POLLIN;
    }

    if ((requested_events & VFS_POLLOUT) != 0 and efd.counter < EVENTFD_MAX_COUNTER) {
        ready |= VFS_POLLOUT;
    }

    return ready;
}

fn pollSignalFd(fd: i32, requested_events: u16) error{BadFd}!u16 {
    const sfd = getSignalFd(fd) orelse return error.BadFd;
    var ready: u16 = 0;

    if ((requested_events & VFS_POLLIN) != 0 and hasReadableSignal(sfd)) {
        ready |= VFS_POLLIN;
    }

    return ready;
}

fn pollInotifyFd(fd: i32, requested_events: u16) error{BadFd}!u16 {
    const inst = getInotifyInstance(fd) orelse return error.BadFd;
    var ready: u16 = 0;

    if ((requested_events & VFS_POLLIN) != 0 and inst.head != inst.tail) {
        ready |= VFS_POLLIN;
    }

    return ready;
}

fn readEventFd(fd: i32, buffer: []u8) i32 {
    const efd = getEventFd(fd) orelse return abi.EBADF;
    if (buffer.len < @sizeOf(u64)) return abi.EINVAL;
    if (efd.counter == 0) return abi.EAGAIN;

    var value: u64 = if ((efd.flags & abi.EFD_SEMAPHORE) != 0) 1 else efd.counter;
    if ((efd.flags & abi.EFD_SEMAPHORE) != 0) {
        efd.counter -= 1;
    } else {
        efd.counter = 0;
    }

    @memcpy(buffer[0..@sizeOf(u64)], std.mem.asBytes(&value));
    readiness.notifyPseudo();
    return @sizeOf(u64);
}

fn readSignalFd(fd: i32, buffer: []u8) i32 {
    const sfd = getSignalFd(fd) orelse return abi.EBADF;
    if (buffer.len < @sizeOf(SignalFdInfo)) return abi.EINVAL;

    var mask = signalFdMask(sfd);
    const info = kernel_signal.takePendingMasked(&mask) orelse return abi.EAGAIN;
    var signal_info = SignalFdInfo{
        .signo = info.si_signo,
        .errno = info.si_errno,
        .code = info.si_code,
        .pid = info.si_pid,
        .uid = info.si_uid,
        .status = info.si_status,
    };

    @memcpy(buffer[0..@sizeOf(SignalFdInfo)], std.mem.asBytes(&signal_info));
    readiness.notifyPseudo();
    return @sizeOf(SignalFdInfo);
}

fn readInotifyFd(fd: i32, buffer: []u8) i32 {
    const inst = getInotifyInstance(fd) orelse return abi.EBADF;
    const event = peekInotifyEvent(inst) orelse return abi.EAGAIN;

    const name_storage_len = alignedNameLength(event.name_len);
    const required = @sizeOf(InotifyEventHeader) + name_storage_len;
    if (buffer.len < required) return abi.EINVAL;

    const header = InotifyEventHeader{
        .wd = event.wd,
        .mask = event.mask,
        .cookie = event.cookie,
        .len = @intCast(name_storage_len),
    };
    @memcpy(buffer[0..@sizeOf(InotifyEventHeader)], std.mem.asBytes(&header));

    if (name_storage_len > 0) {
        @memset(buffer[@sizeOf(InotifyEventHeader) .. @sizeOf(InotifyEventHeader) + name_storage_len], 0);
        @memcpy(
            buffer[@sizeOf(InotifyEventHeader) .. @sizeOf(InotifyEventHeader) + event.name_len],
            event.name[0..event.name_len],
        );
    }

    _ = popInotifyEvent(inst);
    readiness.notifyPseudo();
    return @intCast(required);
}

fn writeEventFd(fd: i32, buffer: []const u8) i32 {
    const efd = getEventFd(fd) orelse return abi.EBADF;
    if (buffer.len != @sizeOf(u64)) return abi.EINVAL;

    var value: u64 = 0;
    @memcpy(std.mem.asBytes(&value), buffer[0..@sizeOf(u64)]);

    if (value == std.math.maxInt(u64)) return abi.EINVAL;
    if (efd.counter > EVENTFD_MAX_COUNTER - value) return abi.EAGAIN;

    efd.counter += value;
    readiness.notifyPseudo();
    return @sizeOf(u64);
}

fn getEventFd(fd: i32) ?*EventFd {
    if (!isEventFd(fd)) return null;
    const idx: usize = @intCast(fd - EVENTFD_BASE);
    const efd = &eventfd_table[idx];
    if (!efd.in_use) return null;
    return efd;
}

fn getSignalFd(fd: i32) ?*SignalFd {
    if (!isSignalFd(fd)) return null;
    const idx: usize = @intCast(fd - SIGNALFD_BASE);
    const sfd = &signalfd_table[idx];
    if (!sfd.in_use) return null;
    return sfd;
}

fn getInotifyInstance(fd: i32) ?*InotifyInstance {
    if (!isInotifyFd(fd)) return null;
    const idx: usize = @intCast(fd - INOTIFY_BASE);
    const inst = &inotify_instances[idx];
    if (!inst.in_use) return null;
    return inst;
}

fn signalFdMask(sfd: *const SignalFd) kernel_signal.SigSet {
    return .{
        .sig = .{
            @truncate(sfd.mask),
            @truncate(sfd.mask >> SIGNALFD_MASK_WORD_BITS),
        },
    };
}

fn hasReadableSignal(sfd: *const SignalFd) bool {
    var mask = signalFdMask(sfd);
    return kernel_signal.hasPendingMasked(&mask);
}

fn resetInotifyInstance(inst: *InotifyInstance) void {
    inst.in_use = false;
    inst.head = 0;
    inst.tail = 0;
    for (&inst.watches) |*watch| {
        watch.in_use = false;
        watch.wd = -1;
    }
}

pub fn notifyInotifyPathEvent(path: []const u8, exact_mask: u32, parent_mask: u32) void {
    for (&inotify_instances) |*inst| {
        if (!inst.in_use) continue;

        for (&inst.watches) |*watch| {
            if (!watch.in_use) continue;

            const watch_path = watch.pathname[0..watch.path_len];
            if (exact_mask != 0 and std.mem.eql(u8, watch_path, path) and (watch.mask & exact_mask) != 0) {
                enqueueInotifyEvent(inst, watch.wd, exact_mask, 0, "");
            }

            if (parent_mask != 0 and parentMatches(watch_path, path) and (watch.mask & parent_mask) != 0) {
                enqueueInotifyEvent(inst, watch.wd, parent_mask, 0, baseName(path));
            }
        }
    }
}

pub fn notifyInotifyRename(old_path: []const u8, new_path: []const u8) void {
    const cookie = nextInotifyCookie();

    for (&inotify_instances) |*inst| {
        if (!inst.in_use) continue;

        for (&inst.watches) |*watch| {
            if (!watch.in_use) continue;
            const watch_path = watch.pathname[0..watch.path_len];

            if (std.mem.eql(u8, watch_path, old_path) and (watch.mask & abi.IN_MOVE_SELF) != 0) {
                enqueueInotifyEvent(inst, watch.wd, abi.IN_MOVE_SELF, cookie, "");
            }

            if (parentMatches(watch_path, old_path) and (watch.mask & abi.IN_MOVED_FROM) != 0) {
                enqueueInotifyEvent(inst, watch.wd, abi.IN_MOVED_FROM, cookie, baseName(old_path));
            }

            if (parentMatches(watch_path, new_path) and (watch.mask & abi.IN_MOVED_TO) != 0) {
                enqueueInotifyEvent(inst, watch.wd, abi.IN_MOVED_TO, cookie, baseName(new_path));
            }
        }
    }
}

fn enqueueInotifyEvent(inst: *InotifyInstance, wd: i32, mask: u32, cookie: u32, name: []const u8) void {
    const next_tail = (inst.tail + 1) % inst.queue.len;
    if (next_tail == inst.head) return;

    const copy_len = @min(name.len, inst.queue[0].name.len);
    var event = &inst.queue[inst.tail];
    event.wd = wd;
    event.mask = mask;
    event.cookie = cookie;
    event.name_len = copy_len;
    @memset(&event.name, 0);
    @memcpy(event.name[0..copy_len], name[0..copy_len]);
    inst.tail = @intCast(next_tail);
    readiness.notifyPseudo();
}

fn peekInotifyEvent(inst: *const InotifyInstance) ?*const InotifyQueuedEvent {
    if (inst.head == inst.tail) return null;
    return &inst.queue[inst.head];
}

fn popInotifyEvent(inst: *InotifyInstance) ?InotifyQueuedEvent {
    if (inst.head == inst.tail) return null;
    const event = inst.queue[inst.head];
    inst.head = @intCast((inst.head + 1) % inst.queue.len);
    return event;
}

fn alignedNameLength(name_len: usize) usize {
    if (name_len == 0) return 0;

    const terminated_name_len = name_len + 1;
    return (terminated_name_len + INOTIFY_NAME_ALIGNMENT - 1) & ~(INOTIFY_NAME_ALIGNMENT - 1);
}

fn timeSpecToTimeoutMilliseconds(ts: syscall_time.TimeSpec) i32 {
    const milliseconds = @as(u64, @intCast(ts.tv_sec)) * MILLISECONDS_PER_SECOND +
        @as(u64, @intCast(@max(0, ts.tv_nsec))) / NANOSECONDS_PER_MILLISECOND;
    return @intCast(@min(milliseconds, MAX_TIMEOUT_MS));
}

fn timeSpecToTimeval(ts: syscall_time.TimeSpec) Timeval {
    return .{
        .tv_sec = ts.tv_sec,
        .tv_usec = @intCast(@max(0, @divTrunc(ts.tv_nsec, NANOSECONDS_PER_MICROSECOND))),
    };
}

fn parentMatches(parent: []const u8, path: []const u8) bool {
    if (parent.len == 0 or !std.mem.startsWith(u8, path, parent)) return false;
    if (path.len <= parent.len) return false;

    if (parent.len == 1 and parent[0] == '/') {
        return std.mem.lastIndexOfScalar(u8, path[1..], '/') == null;
    }

    if (path[parent.len] != '/') return false;
    return std.mem.lastIndexOfScalar(u8, path[parent.len + 1 ..], '/') == null;
}

fn baseName(path: []const u8) []const u8 {
    const idx = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    if (idx + 1 >= path.len) return "";
    return path[idx + 1 ..];
}

fn nextInotifyCookie() u32 {
    const cookie = next_inotify_cookie;
    next_inotify_cookie +%= 1;
    if (next_inotify_cookie == 0) next_inotify_cookie = 1;
    return cookie;
}

fn timeoutDeadline(timeout_ms: i64) ?u64 {
    if (timeout_ms < 0) return null;
    return timer.getTicks() + timer.millisecondsToTicksCeil(@intCast(timeout_ms));
}

fn deadlineReached(deadline_tick: ?u64) bool {
    if (deadline_tick) |deadline| {
        return timer.getTicks() >= deadline;
    }
    return false;
}

fn earliestDeadline(lhs: ?u64, rhs: ?u64) ?u64 {
    if (lhs == null) return rhs;
    if (rhs == null) return lhs;
    return @min(lhs.?, rhs.?);
}

fn observeKernelFd(fd: i32, requested_events: u16, track_deadline: bool) FdObservation {
    if (descriptor.observe(fd, requested_events, track_deadline)) |observation| {
        return .{
            .revents = observation.revents,
            .invalid = observation.invalid,
            .deadline = observation.deadline,
        };
    }

    const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);
    const revents = vfs.pollFd(vfs_fd, requested_events) catch {
        return .{
            .revents = 0,
            .invalid = true,
            .deadline = null,
        };
    };

    return .{
        .revents = revents,
        .invalid = false,
        .deadline = null,
    };
}

fn waitMaskForFd(fd: i32) u32 {
    if (descriptor.lookup(fd)) |known| {
        return switch (known.kind) {
            .inet_socket, .unix_socket => readiness.SOCKET_EVENT_MASK,
            .epoll, .eventfd, .signalfd, .inotify, .timerfd => readiness.PSEUDO_EVENT_MASK,
        };
    }

    return readiness.VFS_EVENT_MASK;
}

fn collectEpollEvents(inst: *const EpollInstance, max: usize, events: *[EPOLL_ENTRY_CAPACITY]EpollEvent, track_deadline: bool) EpollScan {
    var count: usize = 0;
    var earliest: ?u64 = null;
    var wait_mask: u32 = 0;

    for (inst.entries) |maybe_entry| {
        if (maybe_entry) |entry| {
            if (count >= max) break;
            var ready: u32 = 0;

            if (entry.fd >= abi.FD_OFFSET) {
                wait_mask |= waitMaskForFd(entry.fd);
                const requested: u16 = @truncate(entry.events & (abi.EPOLLIN | abi.EPOLLOUT));
                const observation = observeKernelFd(entry.fd, requested, track_deadline and (entry.events & abi.EPOLLIN) != 0);
                earliest = earliestDeadline(earliest, observation.deadline);

                if (observation.invalid) {
                    ready |= abi.EPOLLERR;
                } else {
                    if ((observation.revents & VFS_POLLIN) != 0 and (entry.events & abi.EPOLLIN) != 0) ready |= abi.EPOLLIN;
                    if ((observation.revents & VFS_POLLOUT) != 0 and (entry.events & abi.EPOLLOUT) != 0) ready |= abi.EPOLLOUT;
                }
            }

            if (ready != 0) {
                events[count] = EpollEvent{ .events = ready, .data = entry.data };
                count += 1;
            }
        }
    }

    return .{
        .count = count,
        .earliest_deadline = earliest,
        .wait_mask = wait_mask,
    };
}

fn selectCheckFds(nfds: u32, readfds: *const FdSet, writefds: *const FdSet, exceptfds: *const FdSet, result_readfds: *FdSet, result_writefds: *FdSet, result_exceptfds: *FdSet, track_deadline: bool) ReadyScan {
    result_readfds.* = std.mem.zeroes(FdSet);
    result_writefds.* = std.mem.zeroes(FdSet);
    result_exceptfds.* = std.mem.zeroes(FdSet);

    var count: i32 = 0;
    var earliest: ?u64 = null;
    var wait_mask: u32 = 0;
    var i: u32 = 0;
    while (i < nfds) : (i += 1) {
        const word_idx = i / FD_SET_WORD_BITS;
        const bit_idx: u5 = @intCast(i % FD_SET_WORD_BITS);
        const mask = @as(u32, 1) << bit_idx;

        const wants_read = (readfds.fds_bits[word_idx] & mask) != 0;
        const wants_write = (writefds.fds_bits[word_idx] & mask) != 0;
        const wants_except = (exceptfds.fds_bits[word_idx] & mask) != 0;
        if (!wants_read and !wants_write and !wants_except) continue;

        if (i < abi.FD_OFFSET) {
            if (wants_read and i == abi.STDIN) {
                result_readfds.fds_bits[word_idx] |= mask;
                count += 1;
            }

            if (wants_write and (i == abi.STDOUT or i == abi.STDERR)) {
                result_writefds.fds_bits[word_idx] |= mask;
                count += 1;
            }

            continue;
        }

        wait_mask |= waitMaskForFd(@intCast(i));
        var requested: u16 = 0;
        if (wants_read) requested |= VFS_POLLIN;
        if (wants_write) requested |= VFS_POLLOUT;

        const observation = observeKernelFd(@intCast(i), requested, track_deadline);
        earliest = earliestDeadline(earliest, observation.deadline);

        if (observation.invalid) {
            if (wants_except) {
                result_exceptfds.fds_bits[word_idx] |= mask;
                count += 1;
            }
            continue;
        }

        if (wants_read and (observation.revents & VFS_POLLIN) != 0) {
            result_readfds.fds_bits[word_idx] |= mask;
            count += 1;
        }

        if (wants_write and (observation.revents & VFS_POLLOUT) != 0) {
            result_writefds.fds_bits[word_idx] |= mask;
            count += 1;
        }
    }

    return .{
        .count = count,
        .earliest_deadline = earliest,
        .wait_mask = wait_mask,
    };
}

fn pollCheckFds(kernel_fds: []PollFd, track_deadline: bool) ReadyScan {
    var count: i32 = 0;
    var earliest: ?u64 = null;
    var wait_mask: u32 = 0;
    var i: usize = 0;
    while (i < kernel_fds.len) : (i += 1) {
        kernel_fds[i].revents = 0;
        const fd = kernel_fds[i].fd;

        if (fd < 0) continue;

        if (fd < abi.FD_OFFSET) {
            if (fd == abi.STDIN and (kernel_fds[i].events & POLLIN) != 0) {
                kernel_fds[i].revents |= POLLIN;
                count += 1;
            }
            if ((fd == abi.STDOUT or fd == abi.STDERR) and (kernel_fds[i].events & POLLOUT) != 0) {
                kernel_fds[i].revents |= POLLOUT;
                count += 1;
            }
            continue;
        }

        wait_mask |= waitMaskForFd(fd);
        const requested: u16 = @intCast(kernel_fds[i].events & (POLLIN | POLLOUT));
        const observation = observeKernelFd(fd, requested, track_deadline and (requested & VFS_POLLIN) != 0);
        earliest = earliestDeadline(earliest, observation.deadline);

        if (observation.invalid) {
            kernel_fds[i].revents = POLLNVAL;
            count += 1;
        } else {
            kernel_fds[i].revents = @intCast(observation.revents);
            if (kernel_fds[i].revents != 0) count += 1;
        }
    }

    return .{
        .count = count,
        .earliest_deadline = earliest,
        .wait_mask = wait_mask,
    };
}
