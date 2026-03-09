const std = @import("std");
const abi = @import("abi.zig");
const syscall_time = @import("time.zig");
const protection = @import("../../memory/protection.zig");
const timer = @import("../../timer/timer.zig");
const vfs = @import("../../fs/vfs.zig");

const FdSet = extern struct {
    fds_bits: [8]u32,
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
    entries: [64]?EpollEntry,
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

const InotifyWatch = struct {
    wd: i32,
    pathname: [256]u8,
    path_len: usize,
    mask: u32,
    in_use: bool,
};

const InotifyInstance = struct {
    watches: [16]InotifyWatch,
    flags: u32,
    in_use: bool,
};

const POLLIN: i16 = 0x001;
const POLLOUT: i16 = 0x004;
const POLLNVAL: i16 = 0x020;

const EPOLL_BASE: i32 = abi.FD_OFFSET + 200;
const EPOLL_LIMIT: i32 = EPOLL_BASE + 64;
const EVENTFD_BASE: i32 = 2000;
const EVENTFD_LIMIT: i32 = EVENTFD_BASE + 64;
const SIGNALFD_BASE: i32 = 3000;
const SIGNALFD_LIMIT: i32 = SIGNALFD_BASE + 64;
const INOTIFY_BASE: i32 = 4000;
const INOTIFY_LIMIT: i32 = INOTIFY_BASE + 32;

var epoll_instances: [64]EpollInstance = [_]EpollInstance{.{
    .entries = [_]?EpollEntry{null} ** 64,
    .count = 0,
    .in_use = false,
}} ** 64;

var eventfd_table: [64]EventFd = [_]EventFd{.{ .counter = 0, .flags = 0, .in_use = false }} ** 64;
var signalfd_table: [64]SignalFd = [_]SignalFd{.{ .mask = 0, .flags = 0, .in_use = false }} ** 64;

var inotify_instances: [32]InotifyInstance = [_]InotifyInstance{.{
    .watches = [_]InotifyWatch{.{
        .wd = -1,
        .pathname = [_]u8{0} ** 256,
        .path_len = 0,
        .mask = 0,
        .in_use = false,
    }} ** 16,
    .flags = 0,
    .in_use = false,
}} ** 32;

var next_inotify_wd: i32 = 1;

pub fn closePseudoFd(fd: i32) ?i32 {
    if (isEventFd(fd)) {
        const idx: usize = @intCast(fd - EVENTFD_BASE);
        var efd = &eventfd_table[idx];
        if (!efd.in_use) return abi.EBADF;
        efd.in_use = false;
        return 0;
    }

    if (isSignalFd(fd)) {
        const idx: usize = @intCast(fd - SIGNALFD_BASE);
        var sfd = &signalfd_table[idx];
        if (!sfd.in_use) return abi.EBADF;
        sfd.in_use = false;
        return 0;
    }

    if (isInotifyFd(fd)) {
        const idx: usize = @intCast(fd - INOTIFY_BASE);
        var inst = &inotify_instances[idx];
        if (!inst.in_use) return abi.EBADF;
        resetInotifyInstance(inst);
        return 0;
    }

    if (isEpollFd(fd)) {
        const idx: usize = @intCast(fd - EPOLL_BASE);
        var inst = &epoll_instances[idx];
        if (!inst.in_use) return abi.EBADF;
        inst.in_use = false;
        inst.count = 0;
        return 0;
    }

    return null;
}

pub fn isEpollFd(fd: i32) bool {
    return fd >= EPOLL_BASE and fd < EPOLL_LIMIT;
}

pub fn sys_select(nfds: i32, readfds_addr: usize, writefds_addr: usize, exceptfds_addr: usize, timeout_addr: usize) i32 {
    if (nfds < 0 or nfds > 256) return abi.EINVAL;

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

    var count = selectCheckFds(@intCast(nfds), &readfds, &writefds, &exceptfds, &result_readfds, &result_writefds, &result_exceptfds);

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

    const start_ticks = timer.getTicks();
    const timeout_ticks: u64 = if (timeout_ms < 0) std.math.maxInt(u64) else @as(u64, @intCast(timeout_ms)) / 10;

    while (count == 0) {
        const elapsed = timer.getTicks() - start_ticks;
        if (timeout_ms >= 0 and elapsed >= timeout_ticks) break;

        if (!waitForNextReadinessCheck(start_ticks, timeout_ticks, timeout_ms < 0)) {
            break;
        }
        count = selectCheckFds(@intCast(nfds), &readfds, &writefds, &exceptfds, &result_readfds, &result_writefds, &result_exceptfds);
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
    if (nfds > 256) return abi.EINVAL;

    const copy_size = nfds * @sizeOf(PollFd);
    if (!protection.verifyUserPointer(fds_addr, copy_size)) return abi.EINVAL;

    var kernel_fds: [256]PollFd = undefined;
    protection.copyFromUser(std.mem.asBytes(&kernel_fds)[0..copy_size], fds_addr) catch return abi.EINVAL;

    var count = pollCheckFds(kernel_fds[0..nfds], nfds);

    if (timeout == 0 or count > 0) {
        protection.copyToUser(fds_addr, std.mem.asBytes(&kernel_fds)[0..copy_size]) catch return abi.EINVAL;
        return count;
    }

    const start_ticks = timer.getTicks();
    const timeout_ticks: u64 = if (timeout < 0) std.math.maxInt(u64) else @as(u64, @intCast(timeout)) / 10;

    while (count == 0) {
        const elapsed = timer.getTicks() - start_ticks;
        if (timeout >= 0 and elapsed >= timeout_ticks) break;

        if (!waitForNextReadinessCheck(start_ticks, timeout_ticks, timeout < 0)) {
            break;
        }
        count = pollCheckFds(kernel_fds[0..nfds], nfds);
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
    if (idx < 0 or idx >= 64) return abi.EBADF;
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
    if (idx < 0 or idx >= 64) return abi.EBADF;
    const inst = &epoll_instances[@intCast(idx)];
    if (!inst.in_use) return abi.EBADF;

    if (maxevents <= 0) return abi.EINVAL;
    const max: usize = @intCast(maxevents);
    if (!protection.verifyUserPointer(events_addr, max * @sizeOf(EpollEvent))) return abi.EINVAL;

    var events: [64]EpollEvent = undefined;

    var count = collectEpollEvents(inst, max, &events);
    if (timeout != 0 and count == 0) {
        const start_ticks = timer.getTicks();
        const timeout_ticks: u64 = if (timeout < 0) std.math.maxInt(u64) else @as(u64, @intCast(timeout)) / 10;

        while (count == 0) {
            if (!waitForNextReadinessCheck(start_ticks, timeout_ticks, timeout < 0)) {
                break;
            }
            count = collectEpollEvents(inst, max, &events);
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
                return @intCast(@as(i32, @intCast(i)) + SIGNALFD_BASE);
            }
        }
        return abi.EMFILE;
    }

    if (isSignalFd(fd)) {
        const idx: usize = @intCast(fd - SIGNALFD_BASE);
        if (!signalfd_table[idx].in_use) return abi.EBADF;
        signalfd_table[idx].mask = mask;
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
        const ms: u64 = @as(u64, @intCast(ts.tv_sec)) * 1000 + @as(u64, @intCast(@max(0, ts.tv_nsec))) / 1000000;
        timeout_ms = @intCast(@min(ms, 0x7FFFFFFF));
    }

    return sys_poll(fds_ptr, nfds, timeout_ms);
}

pub fn sys_pselect6(nfds: i32, readfds: usize, writefds: usize, exceptfds: usize, timeout_ptr: usize, sigmask_ptr: usize) i32 {
    _ = sigmask_ptr;

    var timeout_arg: usize = 0;
    var timeval_buf: [8]u8 = undefined;

    if (timeout_ptr != 0) {
        if (!protection.verifyUserPointer(timeout_ptr, @sizeOf(syscall_time.TimeSpec))) return abi.EFAULT;
        var ts: syscall_time.TimeSpec = undefined;
        protection.copyFromUser(std.mem.asBytes(&ts), timeout_ptr) catch return abi.EFAULT;
        if (ts.tv_sec < 0) return abi.EINVAL;

        const tv_sec: u32 = @intCast(ts.tv_sec);
        const tv_usec: u32 = @intCast(@max(0, @divTrunc(ts.tv_nsec, 1000)));
        @memcpy(timeval_buf[0..4], std.mem.asBytes(&tv_sec));
        @memcpy(timeval_buf[4..8], std.mem.asBytes(&tv_usec));
        timeout_arg = @intFromPtr(&timeval_buf);
    }

    return sys_select(nfds, readfds, writefds, exceptfds, timeout_arg);
}

pub fn sys_inotify_init() i32 {
    return sys_inotify_init1(0);
}

pub fn sys_inotify_init1(flags: u32) i32 {
    for (&inotify_instances, 0..) |*inst, i| {
        if (!inst.in_use) {
            inst.in_use = true;
            inst.flags = flags;
            for (&inst.watches) |*watch| {
                watch.in_use = false;
                watch.wd = -1;
            }
            return @intCast(@as(i32, @intCast(i)) + INOTIFY_BASE);
        }
    }
    return abi.EMFILE;
}

pub fn sys_inotify_add_watch(fd: i32, pathname: [*]const u8, mask: u32) i32 {
    if (!isInotifyFd(fd)) return abi.EBADF;
    const idx: usize = @intCast(fd - INOTIFY_BASE);
    if (!inotify_instances[idx].in_use) return abi.EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return abi.EFAULT;

    var path_buffer: [256]u8 = undefined;
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

fn isEventFd(fd: i32) bool {
    return fd >= EVENTFD_BASE and fd < EVENTFD_LIMIT;
}

fn isSignalFd(fd: i32) bool {
    return fd >= SIGNALFD_BASE and fd < SIGNALFD_LIMIT;
}

fn isInotifyFd(fd: i32) bool {
    return fd >= INOTIFY_BASE and fd < INOTIFY_LIMIT;
}

fn resetInotifyInstance(inst: *InotifyInstance) void {
    inst.in_use = false;
    for (&inst.watches) |*watch| {
        watch.in_use = false;
        watch.wd = -1;
    }
}

fn waitForNextReadinessCheck(start_ticks: u64, timeout_ticks: u64, infinite: bool) bool {
    if (!infinite and timer.getTicks() - start_ticks >= timeout_ticks) {
        return false;
    }

    timer.sleepCurrentTicks(1);
    return true;
}

fn collectEpollEvents(inst: *const EpollInstance, max: usize, events: *[64]EpollEvent) usize {
    var count: usize = 0;

    for (inst.entries) |maybe_entry| {
        if (maybe_entry) |entry| {
            if (count >= max) break;
            var ready: u32 = 0;

            if (entry.fd >= abi.FD_OFFSET) {
                const vfs_fd: u32 = @intCast(entry.fd - abi.FD_OFFSET);
                if (vfs.getFileFlags(vfs_fd)) |_| {
                    if (entry.events & abi.EPOLLIN != 0) ready |= abi.EPOLLIN;
                    if (entry.events & abi.EPOLLOUT != 0) ready |= abi.EPOLLOUT;
                } else |_| {
                    ready |= abi.EPOLLERR;
                }
            }

            if (ready != 0) {
                events[count] = EpollEvent{ .events = ready, .data = entry.data };
                count += 1;
            }
        }
    }

    return count;
}

fn selectCheckFds(nfds: u32, readfds: *const FdSet, writefds: *const FdSet, exceptfds: *const FdSet, result_readfds: *FdSet, result_writefds: *FdSet, result_exceptfds: *FdSet) i32 {
    result_readfds.* = std.mem.zeroes(FdSet);
    result_writefds.* = std.mem.zeroes(FdSet);
    result_exceptfds.* = std.mem.zeroes(FdSet);

    var count: i32 = 0;
    var i: u32 = 0;
    while (i < nfds) : (i += 1) {
        const word_idx = i / 32;
        const bit_idx: u5 = @intCast(i % 32);
        const mask = @as(u32, 1) << bit_idx;

        if (readfds.fds_bits[word_idx] & mask != 0) {
            if (i < abi.FD_OFFSET) {
                if (i == abi.STDIN) {
                    result_readfds.fds_bits[word_idx] |= mask;
                    count += 1;
                }
            } else {
                const vfs_fd: u32 = i - abi.FD_OFFSET;
                if (vfs.getFileFlags(vfs_fd)) |_| {
                    result_readfds.fds_bits[word_idx] |= mask;
                    count += 1;
                } else |_| {}
            }
        }

        if (writefds.fds_bits[word_idx] & mask != 0) {
            if (i < abi.FD_OFFSET) {
                if (i == abi.STDOUT or i == abi.STDERR) {
                    result_writefds.fds_bits[word_idx] |= mask;
                    count += 1;
                }
            } else {
                const vfs_fd: u32 = i - abi.FD_OFFSET;
                if (vfs.getFileFlags(vfs_fd)) |_| {
                    result_writefds.fds_bits[word_idx] |= mask;
                    count += 1;
                } else |_| {}
            }
        }

        if (exceptfds.fds_bits[word_idx] & mask != 0) {
            if (i >= abi.FD_OFFSET) {
                const vfs_fd: u32 = i - abi.FD_OFFSET;
                if (vfs.getFileFlags(vfs_fd)) |_| {} else |_| {
                    result_exceptfds.fds_bits[word_idx] |= mask;
                    count += 1;
                }
            }
        }
    }
    return count;
}

fn pollCheckFds(kernel_fds: []PollFd, nfds: u32) i32 {
    var count: i32 = 0;
    var i: u32 = 0;
    while (i < nfds) : (i += 1) {
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

        const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);
        if (vfs.getFileFlags(vfs_fd)) |flags| {
            const access_mode = flags & 0x3;
            if ((kernel_fds[i].events & POLLIN) != 0 and (access_mode == 0 or access_mode == 2)) {
                kernel_fds[i].revents |= POLLIN;
            }
            if ((kernel_fds[i].events & POLLOUT) != 0 and (access_mode == 1 or access_mode == 2)) {
                kernel_fds[i].revents |= POLLOUT;
            }
            if (kernel_fds[i].revents != 0) count += 1;
        } else |_| {
            kernel_fds[i].revents = POLLNVAL;
            count += 1;
        }
    }
    return count;
}
