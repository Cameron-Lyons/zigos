const std = @import("std");
const vga = @import("../drivers/vga.zig");
const process = @import("../process/process.zig");
const socket = @import("../net/socket.zig");
const tcp = @import("../net/tcp.zig");
const ipv4 = @import("../net/ipv4.zig");
const paging = @import("../memory/paging.zig");

var pass_count: u32 = 0;
var fail_count: u32 = 0;

const TCP_TEST_PORT: u16 = 32001;
const TCP_TEST_REMOTE_PORT: u16 = 42001;
const TCP_TEST_PAYLOAD = "wake-path";
const TEST_WAIT_YIELDS: usize = 4096;

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
