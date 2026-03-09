const std = @import("std");
const vga = @import("../drivers/vga.zig");
const process = @import("../process/process.zig");
const protection = @import("../memory/protection.zig");
const socket = @import("../net/socket.zig");
const tcp = @import("../net/tcp.zig");
const ipv4 = @import("../net/ipv4.zig");
const vfs = @import("../fs/vfs.zig");
const paging = @import("../memory/paging.zig");
const kernel_signal = @import("../process/signal.zig");
const syscall = @import("../process/syscall.zig");
const abi = @import("../process/syscall/abi.zig");
const syscall_event = @import("../process/syscall/event.zig");
const syscall_net = @import("../process/syscall/net.zig");
const syscall_time = @import("../process/syscall/time.zig");

var pass_count: u32 = 0;
var fail_count: u32 = 0;

const TCP_TEST_PORT: u16 = 32001;
const TCP_TEST_REMOTE_PORT: u16 = 42001;
const TCP_TEST_PAYLOAD = "wake-path";
const TCP_SELECT_TEST_PORT: u16 = 32011;
const TCP_SELECT_REMOTE_PORT: u16 = 42011;
const UDP_POLL_TEST_PORT: u16 = 32021;
const UDP_POLL_PAYLOAD = "udp-poll";
const UNIX_SELECT_PAYLOAD = "unix-select";
const UNIX_RW_PAYLOAD = "unix-rw";
const EVENTFD_WRITE_VALUE: u64 = 7;
const TIMERFD_INTERVAL_TICKS: u32 = 2;
const SIGNALFD_TEST_SIGNAL: i32 = kernel_signal.SIGUSR1;
const INOTIFY_TEST_PATH = "/inotify-smoke";
const INOTIFY_FD_TEST_PATH = "/inotify-fd-smoke";
const INOTIFY_FD_PAYLOAD = "fd-write";
const INOTIFY_FD_MASK = abi.IN_OPEN | abi.IN_MODIFY | abi.IN_ACCESS | abi.IN_ATTRIB | abi.IN_CLOSE_WRITE;
const TEST_WAIT_YIELDS: usize = 4096;

const FdSet = extern struct {
    fds_bits: [32]u32,
};

const PollFd = extern struct {
    fd: i32,
    events: i16,
    revents: i16,
};

const POLLIN: i16 = 0x001;

const TcpSelectTestState = struct {
    listener_fd: i32 = -1,
    waiter_pid: u32 = 0,
    feeder_pid: u32 = 0,
    done: bool = false,
    ok: bool = false,
};

const UdpPollTestState = struct {
    fd: i32 = -1,
    waiter_pid: u32 = 0,
    feeder_pid: u32 = 0,
    done: bool = false,
    ok: bool = false,
};

const UnixSelectTestState = struct {
    fds: [2]i32 = .{ -1, -1 },
    waiter_pid: u32 = 0,
    feeder_pid: u32 = 0,
    done: bool = false,
    ok: bool = false,
};

const EventFdTestState = struct {
    fd: i32 = -1,
    waiter_pid: u32 = 0,
    feeder_pid: u32 = 0,
    done: bool = false,
    ok: bool = false,
};

const TimerFdTestState = struct {
    fd: i32 = -1,
    waiter_pid: u32 = 0,
    done: bool = false,
    ok: bool = false,
};

const SignalFdTestState = struct {
    fd: i32 = -1,
    waiter_pid: u32 = 0,
    feeder_pid: u32 = 0,
    done: bool = false,
    ok: bool = false,
};

const InotifyTestState = struct {
    fd: i32 = -1,
    wd: i32 = -1,
    waiter_pid: u32 = 0,
    feeder_pid: u32 = 0,
    done: bool = false,
    ok: bool = false,
};

const InotifyFdTestState = struct {
    fd: i32 = -1,
    wd: i32 = -1,
    waiter_pid: u32 = 0,
    feeder_pid: u32 = 0,
    done: bool = false,
    ok: bool = false,
};

const TcpWakeTestState = struct {
    listener: ?*socket.Socket = null,
    accepted: ?*socket.Socket = null,
    accept_done: bool = false,
    accept_ok: bool = false,
    recv_done: bool = false,
    recv_ok: bool = false,
    accept_waiter_pid: u32 = 0,
    accept_feeder_pid: u32 = 0,
    recv_waiter_pid: u32 = 0,
    recv_feeder_pid: u32 = 0,
};

var tcp_wake_test: TcpWakeTestState = .{};
var tcp_select_test: TcpSelectTestState = .{};
var udp_poll_test: UdpPollTestState = .{};
var unix_select_test: UnixSelectTestState = .{};
var eventfd_test: EventFdTestState = .{};
var timerfd_test: TimerFdTestState = .{};
var signalfd_test: SignalFdTestState = .{};
var inotify_test: InotifyTestState = .{};
var inotify_fd_test: InotifyFdTestState = .{};

pub fn test_virtual_memory() bool {
    pass_count = 0;
    fail_count = 0;

    vga.print("\n=== Virtual Memory Test Suite ===\n");

    test_memory_allocation();
    test_page_mapping();
    test_memory_stats();
    test_page_flags();
    test_range_operations();
    test_tcp_accept_recv_wakeup();
    test_tcp_select_readiness();
    test_udp_poll_readiness();
    test_unix_select_readiness();
    test_unix_read_write_dispatch();
    test_eventfd_poll_dispatch();
    test_timerfd_poll_dispatch();
    test_signalfd_poll_dispatch();
    test_inotify_poll_dispatch();
    test_inotify_fd_event_dispatch();

    vga.print("=== VM Test Results: ");
    print_dec(pass_count);
    vga.print(" passed, ");
    print_dec(fail_count);
    vga.print(" failed ===\n");

    if (fail_count == 0) {
        vga.print("=== All VM Tests Passed ===\n\n");
    } else {
        vga.print("=== VM Tests Failed ===\n\n");
    }

    return fail_count == 0;
}

fn test_memory_allocation() void {
    vga.print("Testing memory allocation...\n");

    const ptr1 = paging.kmalloc(1024);
    if (ptr1 == null) {
        vga.print("  [FAIL] Could not allocate 1KB\n");
        fail_count += 1;
        return;
    }
    vga.print("  [OK] Allocated 1KB\n");
    pass_count += 1;

    const ptr2 = paging.kmalloc(4096);
    if (ptr2 == null) {
        vga.print("  [FAIL] Could not allocate 4KB\n");
        fail_count += 1;
        return;
    }
    vga.print("  [OK] Allocated 4KB\n");
    pass_count += 1;

    const ptr3 = paging.kmalloc(8192);
    if (ptr3 == null) {
        vga.print("  [FAIL] Could not allocate 8KB\n");
        fail_count += 1;
        return;
    }
    vga.print("  [OK] Allocated 8KB\n");
    pass_count += 1;

    paging.kfree(ptr1.?);
    vga.print("  [OK] Freed 1KB\n");
    pass_count += 1;

    paging.kfree(ptr2.?);
    vga.print("  [OK] Freed 4KB\n");
    pass_count += 1;

    paging.kfree(ptr3.?);
    vga.print("  [OK] Freed 8KB\n");
    pass_count += 1;
}

fn test_page_mapping() void {
    vga.print("Testing page mapping...\n");

    const virt_addr: u32 = 0x20000000;
    const phys_addr: u32 = 0x400000;

    paging.mapPage(virt_addr, phys_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    vga.print("  [OK] Mapped virtual 0x20000000 to physical 0x400000\n");
    pass_count += 1;

    const retrieved = paging.get_physical_address(virt_addr);
    if (retrieved) |addr| {
        if (addr == phys_addr) {
            vga.print("  [OK] Physical address retrieval correct\n");
            pass_count += 1;
        } else {
            vga.print("  [FAIL] Physical address mismatch\n");
            fail_count += 1;
        }
    } else {
        vga.print("  [FAIL] Could not retrieve physical address\n");
        fail_count += 1;
    }

    if (paging.is_page_present(virt_addr)) {
        vga.print("  [OK] Page presence check passed\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Page should be present\n");
        fail_count += 1;
    }

    paging.unmap_page(virt_addr);
    vga.print("  [OK] Unmapped page\n");
    pass_count += 1;

    if (!paging.is_page_present(virt_addr)) {
        vga.print("  [OK] Page correctly unmapped\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Page should not be present\n");
        fail_count += 1;
    }
}

fn test_memory_stats() void {
    vga.print("Testing memory statistics...\n");

    const stats = paging.getMemoryStats();
    vga.print("  Total frames: ");
    print_dec(stats.total_frames);
    vga.print("\n");
    vga.print("  Used frames: ");
    print_dec(stats.used_frames);
    vga.print("\n");

    const free_frames = stats.total_frames - stats.used_frames;
    vga.print("  Free frames: ");
    print_dec(free_frames);
    vga.print("\n");

    const free_memory = free_frames * 4096 / (1024 * 1024);
    vga.print("  Free memory: ");
    print_dec(free_memory);
    vga.print(" MB\n");
    pass_count += 1;
}

fn test_page_flags() void {
    vga.print("Testing page flags...\n");

    const virt_addr: u32 = 0x21000000;
    const phys_addr: u32 = 0x500000;

    paging.mapPage(virt_addr, phys_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
    vga.print("  [OK] Mapped page with USER flag\n");
    pass_count += 1;

    paging.set_page_flags(virt_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    vga.print("  [OK] Modified page flags (removed USER)\n");
    pass_count += 1;

    paging.set_page_flags(virt_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_GLOBAL);
    vga.print("  [OK] Modified page flags (added GLOBAL)\n");
    pass_count += 1;

    paging.unmap_page(virt_addr);
}

fn test_range_operations() void {
    vga.print("Testing range operations...\n");

    const virt_start: u32 = 0x22000000;
    const phys_start: u32 = 0x600000;
    const size: u32 = 16 * 4096;

    paging.map_range(virt_start, phys_start, size, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    vga.print("  [OK] Mapped 16 pages (64KB) range\n");
    pass_count += 1;

    var all_present = true;
    var i: u32 = 0;
    while (i < size) : (i += 4096) {
        if (!paging.is_page_present(virt_start + i)) {
            all_present = false;
            break;
        }
    }

    if (all_present) {
        vga.print("  [OK] All pages in range are present\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Not all pages in range are present\n");
        fail_count += 1;
    }

    paging.unmap_range(virt_start, size);
    vga.print("  [OK] Unmapped range\n");
    pass_count += 1;

    var all_unmapped = true;
    i = 0;
    while (i < size) : (i += 4096) {
        if (paging.is_page_present(virt_start + i)) {
            all_unmapped = false;
            break;
        }
    }

    if (all_unmapped) {
        vga.print("  [OK] All pages in range are unmapped\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Not all pages in range are unmapped\n");
        fail_count += 1;
    }
}

fn test_tcp_accept_recv_wakeup() void {
    vga.print("Testing TCP accept/recv wakeups...\n");

    resetTcpWakeTest();
    defer cleanupTcpWakeTest();

    const local = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 15 } };

    const listener = socket.createSocket(.STREAM, .TCP) catch {
        vga.print("  [FAIL] Could not create listening socket\n");
        fail_count += 1;
        return;
    };
    tcp_wake_test.listener = listener;

    listener.bind(local, TCP_TEST_PORT) catch {
        vga.print("  [FAIL] Could not bind listening socket\n");
        fail_count += 1;
        return;
    };

    listener.listen(1) catch {
        vga.print("  [FAIL] Could not listen on test socket\n");
        fail_count += 1;
        return;
    };

    const accept_waiter = process.create_process("tcp-accept-wait", tcpAcceptWaitTask);
    tcp_wake_test.accept_waiter_pid = accept_waiter.pid;
    const accept_feeder = process.create_process("tcp-accept-feed", tcpAcceptFeedTask);
    tcp_wake_test.accept_feeder_pid = accept_feeder.pid;

    if (!waitForFlag(&tcp_wake_test.accept_done)) {
        vga.print("  [FAIL] Timed out waiting for accept wakeup\n");
        fail_count += 1;
        return;
    }

    if (!tcp_wake_test.accept_ok or tcp_wake_test.accepted == null) {
        vga.print("  [FAIL] accept did not receive queued client\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] accept woke and returned queued client\n");
    pass_count += 1;

    const recv_waiter = process.create_process("tcp-recv-wait", tcpRecvWaitTask);
    tcp_wake_test.recv_waiter_pid = recv_waiter.pid;
    const recv_feeder = process.create_process("tcp-recv-feed", tcpRecvFeedTask);
    tcp_wake_test.recv_feeder_pid = recv_feeder.pid;

    if (!waitForFlag(&tcp_wake_test.recv_done)) {
        vga.print("  [FAIL] Timed out waiting for recv wakeup\n");
        fail_count += 1;
        return;
    }

    if (!tcp_wake_test.recv_ok) {
        vga.print("  [FAIL] recv did not return expected payload\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] recv woke and returned queued payload\n");
    pass_count += 1;
}

fn test_tcp_select_readiness() void {
    vga.print("Testing select on TCP listener...\n");

    resetTcpSelectTest();
    defer cleanupTcpSelectTest();

    const local = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 15 } };
    const listener_fd = createInetSocket(syscall_net.SOCK_STREAM, local, TCP_SELECT_TEST_PORT, true) orelse {
        vga.print("  [FAIL] Could not create TCP listener fd\n");
        fail_count += 1;
        return;
    };
    tcp_select_test.listener_fd = listener_fd;

    const waiter = process.create_process("tcp-select-wait", tcpSelectWaitTask);
    tcp_select_test.waiter_pid = waiter.pid;
    const feeder = process.create_process("tcp-select-feed", tcpSelectFeedTask);
    tcp_select_test.feeder_pid = feeder.pid;

    if (!waitForFlag(&tcp_select_test.done)) {
        vga.print("  [FAIL] Timed out waiting for TCP select readiness\n");
        fail_count += 1;
        return;
    }

    if (!tcp_select_test.ok) {
        vga.print("  [FAIL] select/accept did not report queued TCP client\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] select marked TCP listener readable\n");
    pass_count += 1;
}

fn test_udp_poll_readiness() void {
    vga.print("Testing poll on UDP socket...\n");

    resetUdpPollTest();
    defer cleanupUdpPollTest();

    const local = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 15 } };
    const fd = createInetSocket(syscall_net.SOCK_DGRAM, local, UDP_POLL_TEST_PORT, false) orelse {
        vga.print("  [FAIL] Could not create UDP socket fd\n");
        fail_count += 1;
        return;
    };
    udp_poll_test.fd = fd;

    const waiter = process.create_process("udp-poll-wait", udpPollWaitTask);
    udp_poll_test.waiter_pid = waiter.pid;
    const feeder = process.create_process("udp-poll-feed", udpPollFeedTask);
    udp_poll_test.feeder_pid = feeder.pid;

    if (!waitForFlag(&udp_poll_test.done)) {
        vga.print("  [FAIL] Timed out waiting for UDP poll readiness\n");
        fail_count += 1;
        return;
    }

    if (!udp_poll_test.ok) {
        vga.print("  [FAIL] poll/recvfrom did not return UDP payload\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] poll marked UDP socket readable\n");
    pass_count += 1;
}

fn test_unix_select_readiness() void {
    vga.print("Testing select on UNIX socketpair...\n");

    resetUnixSelectTest();
    defer cleanupUnixSelectTest();

    const pair_mem = allocUserBytes(@sizeOf([2]i32)) orelse {
        vga.print("  [FAIL] Could not allocate UNIX socketpair buffer\n");
        fail_count += 1;
        return;
    };
    defer freeUserBytes(pair_mem);

    const pair_ptr: *[2]i32 = @ptrCast(@alignCast(pair_mem.ptr));
    const rc = syscall.syscall4(syscall.SYS_SOCKETPAIR, syscall_net.AF_UNIX, syscall_net.SOCK_STREAM, 0, @intFromPtr(pair_ptr));
    if (rc != 0) {
        vga.print("  [FAIL] socketpair syscall failed\n");
        fail_count += 1;
        return;
    }

    unix_select_test.fds = pair_ptr.*;

    const waiter = process.create_process("unix-select-wait", unixSelectWaitTask);
    unix_select_test.waiter_pid = waiter.pid;
    const feeder = process.create_process("unix-select-feed", unixSelectFeedTask);
    unix_select_test.feeder_pid = feeder.pid;

    if (!waitForFlag(&unix_select_test.done)) {
        vga.print("  [FAIL] Timed out waiting for UNIX select readiness\n");
        fail_count += 1;
        return;
    }

    if (!unix_select_test.ok) {
        vga.print("  [FAIL] select/recv did not return UNIX payload\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] select marked UNIX socket readable\n");
    pass_count += 1;
}

fn test_unix_read_write_dispatch() void {
    vga.print("Testing generic read/write on UNIX sockets...\n");

    const pair_mem = allocUserBytes(@sizeOf([2]i32)) orelse {
        vga.print("  [FAIL] Could not allocate UNIX socketpair buffer\n");
        fail_count += 1;
        return;
    };
    defer freeUserBytes(pair_mem);

    const pair_ptr: *[2]i32 = @ptrCast(@alignCast(pair_mem.ptr));
    const socketpair_rc = syscall.syscall4(syscall.SYS_SOCKETPAIR, syscall_net.AF_UNIX, syscall_net.SOCK_STREAM, 0, @intFromPtr(pair_ptr));
    if (socketpair_rc != 0) {
        vga.print("  [FAIL] socketpair syscall failed\n");
        fail_count += 1;
        return;
    }
    defer {
        closeSysFd(pair_ptr[0]);
        closeSysFd(pair_ptr[1]);
    }

    const send_mem = allocUserBytes(UNIX_RW_PAYLOAD.len) orelse {
        vga.print("  [FAIL] Could not allocate UNIX write buffer\n");
        fail_count += 1;
        return;
    };
    defer freeUserBytes(send_mem);
    @memcpy(send_mem, UNIX_RW_PAYLOAD);

    const recv_mem = allocUserBytes(32) orelse {
        vga.print("  [FAIL] Could not allocate UNIX read buffer\n");
        fail_count += 1;
        return;
    };
    defer freeUserBytes(recv_mem);

    const written = syscall.syscall3(syscall.SYS_WRITE, @as(usize, @intCast(pair_ptr[0])), @intFromPtr(send_mem.ptr), send_mem.len);
    if (written != UNIX_RW_PAYLOAD.len) {
        vga.print("  [FAIL] write syscall did not send UNIX payload\n");
        fail_count += 1;
        return;
    }

    const read = syscall.syscall3(syscall.SYS_READ, @as(usize, @intCast(pair_ptr[1])), @intFromPtr(recv_mem.ptr), recv_mem.len);
    if (read != UNIX_RW_PAYLOAD.len or !std.mem.eql(u8, recv_mem[0..@intCast(read)], UNIX_RW_PAYLOAD)) {
        vga.print("  [FAIL] read syscall did not return UNIX payload\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] generic read/write dispatched through special-fd registry\n");
    pass_count += 1;
}

fn test_eventfd_poll_dispatch() void {
    vga.print("Testing eventfd poll/read/write dispatch...\n");

    resetEventFdTest();
    defer cleanupEventFdTest();

    const fd = syscall.syscall2(syscall.SYS_EVENTFD2, 0, 0);
    if (fd < 0) {
        vga.print("  [FAIL] eventfd2 syscall failed\n");
        fail_count += 1;
        return;
    }
    eventfd_test.fd = fd;

    const waiter = process.create_process("eventfd-poll-wait", eventFdPollWaitTask);
    eventfd_test.waiter_pid = waiter.pid;
    const feeder = process.create_process("eventfd-poll-feed", eventFdPollFeedTask);
    eventfd_test.feeder_pid = feeder.pid;

    if (!waitForFlag(&eventfd_test.done)) {
        vga.print("  [FAIL] Timed out waiting for eventfd readiness\n");
        fail_count += 1;
        return;
    }

    if (!eventfd_test.ok) {
        vga.print("  [FAIL] eventfd poll/read/write dispatch failed\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] eventfd woke pollers and transferred value\n");
    pass_count += 1;
}

fn test_timerfd_poll_dispatch() void {
    vga.print("Testing timerfd poll/read dispatch...\n");

    resetTimerFdTest();
    defer cleanupTimerFdTest();

    const fd = syscall.syscall2(syscall.SYS_TIMERFD_CREATE, @as(usize, @intCast(syscall_time.CLOCK_MONOTONIC)), 0);
    if (fd < 0) {
        vga.print("  [FAIL] timerfd_create syscall failed\n");
        fail_count += 1;
        return;
    }
    timerfd_test.fd = fd;

    const spec_mem = allocUserBytes(@sizeOf(syscall_time.ItimerSpec)) orelse {
        vga.print("  [FAIL] Could not allocate timerfd spec buffer\n");
        fail_count += 1;
        return;
    };
    defer freeUserBytes(spec_mem);

    const spec: *syscall_time.ItimerSpec = @ptrCast(@alignCast(spec_mem.ptr));
    spec.* = .{
        .it_interval_sec = 0,
        .it_interval_nsec = 0,
        .it_value_sec = 0,
        .it_value_nsec = TIMERFD_INTERVAL_TICKS * 10_000_000,
    };

    if (syscall.syscall4(syscall.SYS_TIMERFD_SETTIME, @as(usize, @intCast(fd)), 0, @intFromPtr(spec), 0) != 0) {
        vga.print("  [FAIL] timerfd_settime syscall failed\n");
        fail_count += 1;
        return;
    }

    const waiter = process.create_process("timerfd-poll-wait", timerFdPollWaitTask);
    timerfd_test.waiter_pid = waiter.pid;

    if (!waitForFlag(&timerfd_test.done)) {
        vga.print("  [FAIL] Timed out waiting for timerfd readiness\n");
        fail_count += 1;
        return;
    }

    if (!timerfd_test.ok) {
        vga.print("  [FAIL] timerfd poll/read dispatch failed\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] timerfd woke pollers on expiration\n");
    pass_count += 1;
}

fn test_signalfd_poll_dispatch() void {
    vga.print("Testing signalfd poll/read dispatch...\n");

    resetSignalFdTest();
    defer cleanupSignalFdTest();

    const mask_mem = allocUserBytes(@sizeOf(u64)) orelse {
        vga.print("  [FAIL] Could not allocate signalfd mask buffer\n");
        fail_count += 1;
        return;
    };
    defer freeUserBytes(mask_mem);
    storeUserU64(mask_mem, @as(u64, 1) << @intCast(SIGNALFD_TEST_SIGNAL - 1));

    const new_fd_arg: usize = @as(u32, @bitCast(@as(i32, -1)));
    const fd = syscall.syscall4(syscall.SYS_SIGNALFD4, new_fd_arg, @intFromPtr(mask_mem.ptr), @sizeOf(u64), 0);
    if (fd < 0) {
        vga.print("  [FAIL] signalfd4 syscall failed\n");
        fail_count += 1;
        return;
    }
    signalfd_test.fd = fd;

    const waiter = process.create_process("signalfd-poll-wait", signalFdPollWaitTask);
    signalfd_test.waiter_pid = waiter.pid;
    const feeder = process.create_process("signalfd-poll-feed", signalFdPollFeedTask);
    signalfd_test.feeder_pid = feeder.pid;

    if (!waitForFlag(&signalfd_test.done)) {
        vga.print("  [FAIL] Timed out waiting for signalfd readiness\n");
        fail_count += 1;
        return;
    }

    if (!signalfd_test.ok) {
        vga.print("  [FAIL] signalfd poll/read dispatch failed\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] signalfd woke pollers and returned signal info\n");
    pass_count += 1;
}

fn test_inotify_poll_dispatch() void {
    vga.print("Testing inotify poll/read dispatch...\n");

    resetInotifyTest();
    defer cleanupInotifyTest();

    const path_mem = allocUserBytes(INOTIFY_TEST_PATH.len + 1) orelse {
        vga.print("  [FAIL] Could not allocate inotify path buffer\n");
        fail_count += 1;
        return;
    };
    defer freeUserBytes(path_mem);
    @memcpy(path_mem[0..INOTIFY_TEST_PATH.len], INOTIFY_TEST_PATH);
    path_mem[INOTIFY_TEST_PATH.len] = 0;

    const fd = syscall.syscall1(syscall.SYS_INOTIFY_INIT1, 0);
    if (fd < 0) {
        vga.print("  [FAIL] inotify_init1 syscall failed\n");
        fail_count += 1;
        return;
    }
    inotify_test.fd = fd;

    const wd = syscall.syscall3(syscall.SYS_INOTIFY_ADD_WATCH, @as(usize, @intCast(fd)), @intFromPtr(path_mem.ptr), abi.IN_CREATE);
    if (wd < 0) {
        vga.print("  [FAIL] inotify_add_watch syscall failed\n");
        fail_count += 1;
        return;
    }
    inotify_test.wd = wd;

    const waiter = process.create_process("inotify-poll-wait", inotifyPollWaitTask);
    inotify_test.waiter_pid = waiter.pid;
    const feeder = process.create_process("inotify-poll-feed", inotifyPollFeedTask);
    inotify_test.feeder_pid = feeder.pid;

    if (!waitForFlag(&inotify_test.done)) {
        vga.print("  [FAIL] Timed out waiting for inotify readiness\n");
        fail_count += 1;
        return;
    }

    if (!inotify_test.ok) {
        vga.print("  [FAIL] inotify poll/read dispatch failed\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] inotify woke pollers and returned create event\n");
    pass_count += 1;
}

fn test_inotify_fd_event_dispatch() void {
    vga.print("Testing inotify fd-based open/write/close events...\n");

    resetInotifyFdTest();
    defer cleanupInotifyFdTest();

    const path_mem = allocUserBytes(INOTIFY_FD_TEST_PATH.len + 1) orelse {
        vga.print("  [FAIL] Could not allocate inotify file path buffer\n");
        fail_count += 1;
        return;
    };
    defer freeUserBytes(path_mem);
    writeCString(path_mem, INOTIFY_FD_TEST_PATH);

    const create_fd = syscall.syscall2(syscall.SYS_OPEN, @intFromPtr(path_mem.ptr), vfs.O_CREAT | vfs.O_WRONLY | vfs.O_TRUNC);
    if (create_fd < abi.FD_OFFSET) {
        vga.print("  [FAIL] Could not create watched file\n");
        fail_count += 1;
        return;
    }
    closeSysFd(create_fd);

    const fd = syscall.syscall1(syscall.SYS_INOTIFY_INIT1, 0);
    if (fd < 0) {
        vga.print("  [FAIL] inotify_init1 syscall failed for fd events\n");
        fail_count += 1;
        return;
    }
    inotify_fd_test.fd = fd;

    const wd = syscall.syscall3(syscall.SYS_INOTIFY_ADD_WATCH, @as(usize, @intCast(fd)), @intFromPtr(path_mem.ptr), INOTIFY_FD_MASK);
    if (wd < 0) {
        vga.print("  [FAIL] inotify_add_watch failed for file events\n");
        fail_count += 1;
        return;
    }
    inotify_fd_test.wd = wd;

    const waiter = process.create_process("inotify-fd-wait", inotifyFdEventWaitTask);
    inotify_fd_test.waiter_pid = waiter.pid;
    const feeder = process.create_process("inotify-fd-feed", inotifyFdEventFeedTask);
    inotify_fd_test.feeder_pid = feeder.pid;

    if (!waitForFlag(&inotify_fd_test.done)) {
        vga.print("  [FAIL] Timed out waiting for fd-based inotify events\n");
        fail_count += 1;
        return;
    }

    if (!inotify_fd_test.ok) {
        vga.print("  [FAIL] missing inotify fd access/attrib events\n");
        fail_count += 1;
        return;
    }

    vga.print("  [OK] inotify reported fd open/write/read/attrib/close events\n");
    pass_count += 1;
}

fn resetTcpSelectTest() void {
    tcp_select_test = .{};
}

fn cleanupTcpSelectTest() void {
    terminateTestProcess(tcp_select_test.waiter_pid);
    terminateTestProcess(tcp_select_test.feeder_pid);
    closeSysFd(tcp_select_test.listener_fd);
    tcp_select_test = .{};
}

fn resetUdpPollTest() void {
    udp_poll_test = .{};
}

fn cleanupUdpPollTest() void {
    terminateTestProcess(udp_poll_test.waiter_pid);
    terminateTestProcess(udp_poll_test.feeder_pid);
    closeSysFd(udp_poll_test.fd);
    udp_poll_test = .{};
}

fn resetUnixSelectTest() void {
    unix_select_test = .{};
}

fn resetEventFdTest() void {
    eventfd_test = .{};
}

fn resetTimerFdTest() void {
    timerfd_test = .{};
}

fn resetSignalFdTest() void {
    signalfd_test = .{};
}

fn resetInotifyTest() void {
    inotify_test = .{};
}

fn resetInotifyFdTest() void {
    inotify_fd_test = .{};
}

fn cleanupUnixSelectTest() void {
    terminateTestProcess(unix_select_test.waiter_pid);
    terminateTestProcess(unix_select_test.feeder_pid);
    closeSysFd(unix_select_test.fds[0]);
    closeSysFd(unix_select_test.fds[1]);
    unix_select_test = .{};
}

fn cleanupEventFdTest() void {
    terminateTestProcess(eventfd_test.waiter_pid);
    terminateTestProcess(eventfd_test.feeder_pid);
    closeSysFd(eventfd_test.fd);
    eventfd_test = .{};
}

fn cleanupTimerFdTest() void {
    terminateTestProcess(timerfd_test.waiter_pid);
    closeSysFd(timerfd_test.fd);
    timerfd_test = .{};
}

fn cleanupSignalFdTest() void {
    terminateTestProcess(signalfd_test.waiter_pid);
    terminateTestProcess(signalfd_test.feeder_pid);
    closeSysFd(signalfd_test.fd);
    signalfd_test = .{};
}

fn cleanupInotifyTest() void {
    terminateTestProcess(inotify_test.waiter_pid);
    terminateTestProcess(inotify_test.feeder_pid);
    closeSysFd(inotify_test.fd);

    const path_mem = allocUserBytes(INOTIFY_TEST_PATH.len + 1) orelse {
        inotify_test = .{};
        return;
    };
    defer freeUserBytes(path_mem);
    @memcpy(path_mem[0..INOTIFY_TEST_PATH.len], INOTIFY_TEST_PATH);
    path_mem[INOTIFY_TEST_PATH.len] = 0;
    _ = syscall.syscall1(syscall.SYS_RMDIR, @intFromPtr(path_mem.ptr));
    inotify_test = .{};
}

fn cleanupInotifyFdTest() void {
    terminateTestProcess(inotify_fd_test.waiter_pid);
    terminateTestProcess(inotify_fd_test.feeder_pid);
    closeSysFd(inotify_fd_test.fd);

    const path_mem = allocUserBytes(INOTIFY_FD_TEST_PATH.len + 1) orelse {
        inotify_fd_test = .{};
        return;
    };
    defer freeUserBytes(path_mem);
    writeCString(path_mem, INOTIFY_FD_TEST_PATH);
    _ = syscall.syscall1(syscall.SYS_UNLINK, @intFromPtr(path_mem.ptr));
    inotify_fd_test = .{};
}

fn tcpSelectWaitTask() void {
    const listener_fd = tcp_select_test.listener_fd;
    if (listener_fd < 0) {
        tcp_select_test.done = true;
        finishTestTask();
    }

    const readfds_mem = allocUserBytes(@sizeOf(FdSet)) orelse {
        tcp_select_test.done = true;
        finishTestTask();
    };
    defer freeUserBytes(readfds_mem);

    const readfds: *FdSet = @ptrCast(@alignCast(readfds_mem.ptr));
    setFd(readfds, listener_fd);

    const ready = syscall.syscall5(syscall.SYS_SELECT, @as(usize, @intCast(listener_fd + 1)), @intFromPtr(readfds), 0, 0, 0);
    if (ready == 1 and isFdSet(readfds, listener_fd)) {
        const accepted_fd = syscall.syscall4(syscall.SYS_ACCEPT4, @as(usize, @intCast(listener_fd)), 0, 0, 0);
        if (accepted_fd >= syscall_net.socket_fd_base) {
            closeSysFd(accepted_fd);
            tcp_select_test.ok = true;
        }
    }

    tcp_select_test.done = true;
    finishTestTask();
}

fn tcpSelectFeedTask() void {
    process.yield();

    const listener = syscall_net.getInetSocket(tcp_select_test.listener_fd) orelse {
        finishTestTask();
    };

    const remote = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 99 } };
    const conn = tcp.createConnection(listener.local_addr, listener.local_port, remote, TCP_SELECT_REMOTE_PORT) catch {
        finishTestTask();
    };
    conn.state = .ESTABLISHED;

    const client = socket.createAcceptedTcpSocket(conn, listener.local_addr, listener.local_port, remote, TCP_SELECT_REMOTE_PORT) catch {
        tcp.releaseConnection(conn);
        finishTestTask();
    };

    listener.addToBacklog(client) catch {
        client.close();
        finishTestTask();
    };

    finishTestTask();
}

fn udpPollWaitTask() void {
    const fd = udp_poll_test.fd;
    if (fd < 0) {
        udp_poll_test.done = true;
        finishTestTask();
    }

    const poll_mem = allocUserBytes(@sizeOf(PollFd)) orelse {
        udp_poll_test.done = true;
        finishTestTask();
    };
    defer freeUserBytes(poll_mem);

    const poll_fd: *PollFd = @ptrCast(@alignCast(poll_mem.ptr));
    poll_fd.* = .{ .fd = fd, .events = POLLIN, .revents = 0 };

    const timeout_arg: usize = @as(u32, @bitCast(@as(i32, -1)));
    const ready = syscall.syscall3(syscall.SYS_POLL, @intFromPtr(poll_fd), 1, timeout_arg);
    if (ready == 1 and (poll_fd.revents & POLLIN) != 0) {
        const recv_mem = allocUserBytes(32) orelse {
            udp_poll_test.done = true;
            finishTestTask();
        };
        defer freeUserBytes(recv_mem);

        const received = syscall.syscall5(syscall.SYS_RECVFROM, @as(usize, @intCast(fd)), @intFromPtr(recv_mem.ptr), recv_mem.len, 0, 0);
        if (received == UDP_POLL_PAYLOAD.len and std.mem.eql(u8, recv_mem[0..@intCast(received)], UDP_POLL_PAYLOAD)) {
            udp_poll_test.ok = true;
        }
    }

    udp_poll_test.done = true;
    finishTestTask();
}

fn udpPollFeedTask() void {
    process.yield();

    const sock = syscall_net.getInetSocket(udp_poll_test.fd) orelse {
        finishTestTask();
    };
    sock.addToRecvBuffer(UDP_POLL_PAYLOAD);
    finishTestTask();
}

fn unixSelectWaitTask() void {
    const fd = unix_select_test.fds[0];
    if (fd < 0) {
        unix_select_test.done = true;
        finishTestTask();
    }

    const readfds_mem = allocUserBytes(@sizeOf(FdSet)) orelse {
        unix_select_test.done = true;
        finishTestTask();
    };
    defer freeUserBytes(readfds_mem);

    const readfds: *FdSet = @ptrCast(@alignCast(readfds_mem.ptr));
    setFd(readfds, fd);

    const ready = syscall.syscall5(syscall.SYS_SELECT, @as(usize, @intCast(fd + 1)), @intFromPtr(readfds), 0, 0, 0);
    if (ready == 1 and isFdSet(readfds, fd)) {
        const recv_mem = allocUserBytes(32) orelse {
            unix_select_test.done = true;
            finishTestTask();
        };
        defer freeUserBytes(recv_mem);

        const received = syscall.syscall3(syscall.SYS_RECV, @as(usize, @intCast(fd)), @intFromPtr(recv_mem.ptr), recv_mem.len);
        if (received == UNIX_SELECT_PAYLOAD.len and std.mem.eql(u8, recv_mem[0..@intCast(received)], UNIX_SELECT_PAYLOAD)) {
            unix_select_test.ok = true;
        }
    }

    unix_select_test.done = true;
    finishTestTask();
}

fn unixSelectFeedTask() void {
    process.yield();

    const fd = unix_select_test.fds[1];
    if (fd < 0) {
        finishTestTask();
    }

    const send_mem = allocUserBytes(UNIX_SELECT_PAYLOAD.len) orelse {
        finishTestTask();
    };
    defer freeUserBytes(send_mem);

    @memcpy(send_mem, UNIX_SELECT_PAYLOAD);
    _ = syscall.syscall3(syscall.SYS_SEND, @as(usize, @intCast(fd)), @intFromPtr(send_mem.ptr), send_mem.len);
    finishTestTask();
}

fn eventFdPollWaitTask() void {
    const fd = eventfd_test.fd;
    if (fd < 0) {
        eventfd_test.done = true;
        finishTestTask();
    }

    const poll_mem = allocUserBytes(@sizeOf(PollFd)) orelse {
        eventfd_test.done = true;
        finishTestTask();
    };
    defer freeUserBytes(poll_mem);

    const poll_fd: *PollFd = @ptrCast(@alignCast(poll_mem.ptr));
    poll_fd.* = .{ .fd = fd, .events = POLLIN, .revents = 0 };

    const timeout_arg: usize = @as(u32, @bitCast(@as(i32, -1)));
    const ready = syscall.syscall3(syscall.SYS_POLL, @intFromPtr(poll_fd), 1, timeout_arg);
    if (ready == 1 and (poll_fd.revents & POLLIN) != 0) {
        const value_mem = allocUserBytes(@sizeOf(u64)) orelse {
            eventfd_test.done = true;
            finishTestTask();
        };
        defer freeUserBytes(value_mem);

        const read = syscall.syscall3(syscall.SYS_READ, @as(usize, @intCast(fd)), @intFromPtr(value_mem.ptr), value_mem.len);
        if (read == @sizeOf(u64) and loadUserU64(value_mem) == EVENTFD_WRITE_VALUE) {
            eventfd_test.ok = true;
        }
    }

    eventfd_test.done = true;
    finishTestTask();
}

fn eventFdPollFeedTask() void {
    process.yield();

    const fd = eventfd_test.fd;
    if (fd < 0) {
        finishTestTask();
    }

    const value_mem = allocUserBytes(@sizeOf(u64)) orelse {
        finishTestTask();
    };
    defer freeUserBytes(value_mem);

    storeUserU64(value_mem, EVENTFD_WRITE_VALUE);
    _ = syscall.syscall3(syscall.SYS_WRITE, @as(usize, @intCast(fd)), @intFromPtr(value_mem.ptr), value_mem.len);
    finishTestTask();
}

fn timerFdPollWaitTask() void {
    const fd = timerfd_test.fd;
    if (fd < 0) {
        timerfd_test.done = true;
        finishTestTask();
    }

    const poll_mem = allocUserBytes(@sizeOf(PollFd)) orelse {
        timerfd_test.done = true;
        finishTestTask();
    };
    defer freeUserBytes(poll_mem);

    const poll_fd: *PollFd = @ptrCast(@alignCast(poll_mem.ptr));
    poll_fd.* = .{ .fd = fd, .events = POLLIN, .revents = 0 };

    const timeout_arg: usize = @as(u32, @bitCast(@as(i32, -1)));
    const ready = syscall.syscall3(syscall.SYS_POLL, @intFromPtr(poll_fd), 1, timeout_arg);
    if (ready == 1 and (poll_fd.revents & POLLIN) != 0) {
        const value_mem = allocUserBytes(@sizeOf(u64)) orelse {
            timerfd_test.done = true;
            finishTestTask();
        };
        defer freeUserBytes(value_mem);

        const read = syscall.syscall3(syscall.SYS_READ, @as(usize, @intCast(fd)), @intFromPtr(value_mem.ptr), value_mem.len);
        const expirations = loadUserU64(value_mem);
        if (read == @sizeOf(u64) and expirations >= 1) {
            timerfd_test.ok = true;
        }
    }

    timerfd_test.done = true;
    finishTestTask();
}

fn signalFdPollWaitTask() void {
    const fd = signalfd_test.fd;
    if (fd < 0) {
        signalfd_test.done = true;
        finishTestTask();
    }

    const sigset_mem = allocUserBytes(@sizeOf(kernel_signal.SigSet)) orelse {
        signalfd_test.done = true;
        finishTestTask();
    };
    defer freeUserBytes(sigset_mem);

    const sigset: *kernel_signal.SigSet = @ptrCast(@alignCast(sigset_mem.ptr));
    sigset.* = kernel_signal.SigSet.empty();
    sigset.add(SIGNALFD_TEST_SIGNAL);
    _ = syscall.syscall3(syscall.SYS_SIGPROCMASK, 1, @intFromPtr(sigset), 0);

    const poll_mem = allocUserBytes(@sizeOf(PollFd)) orelse {
        signalfd_test.done = true;
        finishTestTask();
    };
    defer freeUserBytes(poll_mem);

    const poll_fd: *PollFd = @ptrCast(@alignCast(poll_mem.ptr));
    poll_fd.* = .{ .fd = fd, .events = POLLIN, .revents = 0 };

    const timeout_arg: usize = @as(u32, @bitCast(@as(i32, -1)));
    const ready = syscall.syscall3(syscall.SYS_POLL, @intFromPtr(poll_fd), 1, timeout_arg);
    if (ready == 1 and (poll_fd.revents & POLLIN) != 0) {
        const info_mem = allocUserBytes(@sizeOf(syscall_event.SignalFdInfo)) orelse {
            signalfd_test.done = true;
            finishTestTask();
        };
        defer freeUserBytes(info_mem);

        const read = syscall.syscall3(syscall.SYS_READ, @as(usize, @intCast(fd)), @intFromPtr(info_mem.ptr), info_mem.len);
        const info: *syscall_event.SignalFdInfo = @ptrCast(@alignCast(info_mem.ptr));
        if (read == @sizeOf(syscall_event.SignalFdInfo) and info.signo == SIGNALFD_TEST_SIGNAL) {
            signalfd_test.ok = true;
        }
    }

    signalfd_test.done = true;
    finishTestTask();
}

fn signalFdPollFeedTask() void {
    process.yield();

    if (signalfd_test.waiter_pid == 0) {
        finishTestTask();
    }

    _ = syscall.syscall2(syscall.SYS_KILL, signalfd_test.waiter_pid, @as(usize, @intCast(SIGNALFD_TEST_SIGNAL)));
    finishTestTask();
}

fn inotifyPollWaitTask() void {
    const fd = inotify_test.fd;
    if (fd < 0) {
        inotify_test.done = true;
        finishTestTask();
    }

    const poll_mem = allocUserBytes(@sizeOf(PollFd)) orelse {
        inotify_test.done = true;
        finishTestTask();
    };
    defer freeUserBytes(poll_mem);

    const poll_fd: *PollFd = @ptrCast(@alignCast(poll_mem.ptr));
    poll_fd.* = .{ .fd = fd, .events = POLLIN, .revents = 0 };

    const timeout_arg: usize = @as(u32, @bitCast(@as(i32, -1)));
    const ready = syscall.syscall3(syscall.SYS_POLL, @intFromPtr(poll_fd), 1, timeout_arg);
    if (ready == 1 and (poll_fd.revents & POLLIN) != 0) {
        const event_mem = allocUserBytes(@sizeOf(syscall_event.InotifyEventHeader) + 16) orelse {
            inotify_test.done = true;
            finishTestTask();
        };
        defer freeUserBytes(event_mem);

        const read = syscall.syscall3(syscall.SYS_READ, @as(usize, @intCast(fd)), @intFromPtr(event_mem.ptr), event_mem.len);
        const event: *syscall_event.InotifyEventHeader = @ptrCast(@alignCast(event_mem.ptr));
        if (read >= @sizeOf(syscall_event.InotifyEventHeader) and event.wd == inotify_test.wd and (event.mask & abi.IN_CREATE) != 0) {
            inotify_test.ok = true;
        }
    }

    inotify_test.done = true;
    finishTestTask();
}

fn inotifyPollFeedTask() void {
    process.yield();

    const path_mem = allocUserBytes(INOTIFY_TEST_PATH.len + 1) orelse {
        finishTestTask();
    };
    defer freeUserBytes(path_mem);
    @memcpy(path_mem[0..INOTIFY_TEST_PATH.len], INOTIFY_TEST_PATH);
    path_mem[INOTIFY_TEST_PATH.len] = 0;

    _ = syscall.syscall2(syscall.SYS_MKDIR, @intFromPtr(path_mem.ptr), 0o755);
    finishTestTask();
}

fn inotifyFdEventWaitTask() void {
    const fd = inotify_fd_test.fd;
    if (fd < 0) {
        inotify_fd_test.done = true;
        finishTestTask();
    }

    var seen_mask: u32 = 0;
    var attempts: usize = 0;

    while (attempts < 12 and seen_mask != INOTIFY_FD_MASK) : (attempts += 1) {
        const poll_mem = allocUserBytes(@sizeOf(PollFd)) orelse {
            inotify_fd_test.done = true;
            finishTestTask();
        };
        defer freeUserBytes(poll_mem);

        const poll_fd: *PollFd = @ptrCast(@alignCast(poll_mem.ptr));
        poll_fd.* = .{ .fd = fd, .events = POLLIN, .revents = 0 };
        const timeout_arg: usize = if (attempts == 0) @as(u32, @bitCast(@as(i32, -1))) else 0;

        const ready = syscall.syscall3(syscall.SYS_POLL, @intFromPtr(poll_fd), 1, timeout_arg);
        if (ready == 1 and (poll_fd.revents & POLLIN) != 0) {
            const event_mem = allocUserBytes(@sizeOf(syscall_event.InotifyEventHeader) + 16) orelse {
                inotify_fd_test.done = true;
                finishTestTask();
            };
            defer freeUserBytes(event_mem);

            const read = syscall.syscall3(syscall.SYS_READ, @as(usize, @intCast(fd)), @intFromPtr(event_mem.ptr), event_mem.len);
            if (read >= @sizeOf(syscall_event.InotifyEventHeader)) {
                const event: *syscall_event.InotifyEventHeader = @ptrCast(@alignCast(event_mem.ptr));
                if (event.wd == inotify_fd_test.wd) {
                    seen_mask |= event.mask & INOTIFY_FD_MASK;
                }
            }
        } else {
            process.yield();
        }
    }

    inotify_fd_test.ok = seen_mask == INOTIFY_FD_MASK;
    inotify_fd_test.done = true;
    finishTestTask();
}

fn inotifyFdEventFeedTask() void {
    process.yield();

    const path_mem = allocUserBytes(INOTIFY_FD_TEST_PATH.len + 1) orelse {
        finishTestTask();
    };
    defer freeUserBytes(path_mem);
    writeCString(path_mem, INOTIFY_FD_TEST_PATH);

    const fd = syscall.syscall2(syscall.SYS_OPEN, @intFromPtr(path_mem.ptr), vfs.O_RDWR);
    if (fd < abi.FD_OFFSET) {
        finishTestTask();
    }
    defer closeSysFd(fd);

    const data_mem = allocUserBytes(INOTIFY_FD_PAYLOAD.len) orelse {
        finishTestTask();
    };
    defer freeUserBytes(data_mem);
    @memcpy(data_mem, INOTIFY_FD_PAYLOAD);

    _ = syscall.syscall3(syscall.SYS_WRITE, @as(usize, @intCast(fd)), @intFromPtr(data_mem.ptr), data_mem.len);

    const mode: usize = 0o640;
    _ = syscall.syscall2(syscall.SYS_FCHMOD, @as(usize, @intCast(fd)), mode);
    _ = syscall.syscall3(syscall.SYS_FCHOWN, @as(usize, @intCast(fd)), 0, 0);

    const rewind_result = syscall.syscall3(syscall.SYS_LSEEK, @as(usize, @intCast(fd)), 0, vfs.SEEK_SET);
    if (rewind_result >= 0) {
        const read_mem = allocUserBytes(INOTIFY_FD_PAYLOAD.len) orelse {
            finishTestTask();
        };
        defer freeUserBytes(read_mem);
        _ = syscall.syscall3(syscall.SYS_READ, @as(usize, @intCast(fd)), @intFromPtr(read_mem.ptr), read_mem.len);
    }

    finishTestTask();
}

fn createInetSocket(sock_type: u32, addr: ipv4.IPv4Address, port: u16, listen: bool) ?i32 {
    const fd = syscall.syscall3(syscall.SYS_SOCKET, syscall_net.AF_INET, sock_type, 0);
    if (fd < syscall_net.socket_fd_base) return null;
    errdefer closeSysFd(fd);

    const addr_mem = allocUserBytes(@sizeOf(syscall_net.SockAddrIn)) orelse return null;
    defer freeUserBytes(addr_mem);

    const sock_addr: *syscall_net.SockAddrIn = @ptrCast(@alignCast(addr_mem.ptr));
    sock_addr.* = .{
        .family = @intCast(syscall_net.AF_INET),
        .port = @byteSwap(port),
        .addr = ipv4ToSysAddr(addr),
        .zero = [_]u8{0} ** 8,
    };

    if (syscall.syscall3(syscall.SYS_BIND, @as(usize, @intCast(fd)), @intFromPtr(sock_addr), @sizeOf(syscall_net.SockAddrIn)) != 0) {
        return null;
    }

    if (listen) {
        if (syscall.syscall2(syscall.SYS_LISTEN, @as(usize, @intCast(fd)), 1) != 0) {
            return null;
        }
    }

    return fd;
}

fn ipv4ToSysAddr(addr: ipv4.IPv4Address) u32 {
    return (@as(u32, addr.octets[0]) << 0) |
        (@as(u32, addr.octets[1]) << 8) |
        (@as(u32, addr.octets[2]) << 16) |
        (@as(u32, addr.octets[3]) << 24);
}

fn allocUserBytes(size: usize) ?[]u8 {
    const addr = protection.allocateUserMemory(size, protection.PROT_READ | protection.PROT_WRITE) catch return null;
    const ptr: [*]u8 = @ptrFromInt(addr);
    const slice = ptr[0..size];
    @memset(slice, 0);
    return slice;
}

fn freeUserBytes(bytes: []u8) void {
    protection.freeUserMemory(@intFromPtr(bytes.ptr), bytes.len);
}

fn writeCString(bytes: []u8, value: []const u8) void {
    @memset(bytes, 0);
    @memcpy(bytes[0..value.len], value);
}

fn setFd(fdset: *FdSet, fd: i32) void {
    const fd_u32: u32 = @intCast(fd);
    const word_idx = fd_u32 / 32;
    const bit_idx: u5 = @intCast(fd_u32 % 32);
    fdset.fds_bits[word_idx] |= @as(u32, 1) << bit_idx;
}

fn isFdSet(fdset: *const FdSet, fd: i32) bool {
    const fd_u32: u32 = @intCast(fd);
    const word_idx = fd_u32 / 32;
    const bit_idx: u5 = @intCast(fd_u32 % 32);
    return (fdset.fds_bits[word_idx] & (@as(u32, 1) << bit_idx)) != 0;
}

fn closeSysFd(fd: i32) void {
    if (fd >= 0) {
        _ = syscall.syscall1(syscall.SYS_CLOSE, @as(usize, @intCast(fd)));
    }
}

fn storeUserU64(bytes: []u8, value: u64) void {
    const value_ptr: *u64 = @ptrCast(@alignCast(bytes.ptr));
    value_ptr.* = value;
}

fn loadUserU64(bytes: []const u8) u64 {
    const value_ptr: *const u64 = @ptrCast(@alignCast(bytes.ptr));
    return value_ptr.*;
}

fn resetTcpWakeTest() void {
    tcp_wake_test = .{};
}

fn cleanupTcpWakeTest() void {
    terminateTestProcess(tcp_wake_test.recv_waiter_pid);
    terminateTestProcess(tcp_wake_test.recv_feeder_pid);
    terminateTestProcess(tcp_wake_test.accept_waiter_pid);
    terminateTestProcess(tcp_wake_test.accept_feeder_pid);

    if (tcp_wake_test.accepted) |client| {
        if (client.in_use) {
            client.close();
        }
    }

    if (tcp_wake_test.listener) |listener| {
        if (listener.in_use) {
            listener.close();
        }
    }

    tcp_wake_test = .{};
}

fn terminateTestProcess(pid: u32) void {
    if (pid == 0) return;
    _ = process.terminateProcess(pid);
}

fn waitForFlag(flag: *const bool) bool {
    var remaining = TEST_WAIT_YIELDS;
    while (remaining > 0) : (remaining -= 1) {
        if (flag.*) return true;
        process.yield();
    }
    return flag.*;
}

fn tcpAcceptWaitTask() void {
    const listener = tcp_wake_test.listener orelse {
        tcp_wake_test.accept_done = true;
        finishTestTask();
    };

    const client = listener.accept() catch {
        tcp_wake_test.accept_done = true;
        finishTestTask();
    };

    tcp_wake_test.accepted = client;
    tcp_wake_test.accept_ok = client.state == .CONNECTED and client.tcp_connection != null;
    tcp_wake_test.accept_done = true;
    finishTestTask();
}

fn tcpAcceptFeedTask() void {
    process.yield();

    const listener = tcp_wake_test.listener orelse {
        tcp_wake_test.accept_done = true;
        finishTestTask();
    };

    const remote = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 99 } };
    const conn = tcp.createConnection(listener.local_addr, listener.local_port, remote, TCP_TEST_REMOTE_PORT) catch {
        tcp_wake_test.accept_done = true;
        finishTestTask();
    };
    conn.state = .ESTABLISHED;

    const client = socket.createAcceptedTcpSocket(conn, listener.local_addr, listener.local_port, remote, TCP_TEST_REMOTE_PORT) catch {
        tcp.releaseConnection(conn);
        tcp_wake_test.accept_done = true;
        finishTestTask();
    };

    listener.addToBacklog(client) catch {
        client.close();
        tcp_wake_test.accept_done = true;
        finishTestTask();
    };

    finishTestTask();
}

fn tcpRecvWaitTask() void {
    const client = tcp_wake_test.accepted orelse {
        tcp_wake_test.recv_done = true;
        finishTestTask();
    };

    var buffer: [32]u8 = undefined;
    const bytes_read = client.recv(&buffer) catch {
        tcp_wake_test.recv_done = true;
        finishTestTask();
    };

    tcp_wake_test.recv_ok = bytes_read == TCP_TEST_PAYLOAD.len and std.mem.eql(u8, buffer[0..bytes_read], TCP_TEST_PAYLOAD);
    tcp_wake_test.recv_done = true;
    finishTestTask();
}

fn tcpRecvFeedTask() void {
    process.yield();

    const client = tcp_wake_test.accepted orelse {
        tcp_wake_test.recv_done = true;
        finishTestTask();
    };

    const conn = client.tcp_connection orelse {
        tcp_wake_test.recv_done = true;
        finishTestTask();
    };

    @memcpy(conn.recv_buffer[0..TCP_TEST_PAYLOAD.len], TCP_TEST_PAYLOAD);
    conn.recv_buffer_used = TCP_TEST_PAYLOAD.len;
    conn.ready.signal();
    finishTestTask();
}

fn finishTestTask() noreturn {
    _ = process.terminateProcess(process.getCurrentPID());
    while (true) {
        process.yield();
    }
}

fn print_dec(value: u32) void {
    if (value == 0) {
        vga.put_char('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
    var buffer: [10]u8 = undefined;
    var i: usize = 0;
    var n = value;

    while (n > 0) : (i += 1) {
        buffer[i] = @truncate((n % 10) + '0');
        n /= 10;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}
