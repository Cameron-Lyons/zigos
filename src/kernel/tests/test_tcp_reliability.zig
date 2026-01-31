// zlint-disable suppressed-errors
const vga = @import("../drivers/vga.zig");
const tcp = @import("../net/tcp.zig");
const ipv4 = @import("../net/ipv4.zig");

var pass_count: u32 = 0;
var fail_count: u32 = 0;

pub fn runTCPReliabilityTests() void {
    pass_count = 0;
    fail_count = 0;

    vga.print("\n=== TCP Reliability Tests ===\n\n");

    testListenSocket();
    testCreateConnection();
    testConnectionInitialState();
    testCongestionWindowDefaults();
    testSendOnClosedConnection();
    testReceiveEmptyBuffer();
    testTickNoConnections();
    testMultipleListenSockets();

    vga.print("\n--- Results: ");
    printDec(pass_count);
    vga.print(" passed, ");
    printDec(fail_count);
    vga.print(" failed ---\n");
    vga.print("=== TCP Reliability Tests Complete ===\n");
}

fn testListenSocket() void {
    vga.print("Test 1: Create listening socket\n");
    const sock_id = tcp.listen(8080) catch |err| {
        vga.print("  [FAIL] listen: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    vga.print("  [OK] Listening socket created (id ");
    printDec(@intCast(sock_id));
    vga.print(")\n");
    pass_count += 1;

    tcp.close(sock_id) catch {};
}

fn testCreateConnection() void {
    vga.print("Test 2: Create TCP connection\n");
    const local = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 15 } };
    const remote = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 1 } };

    const conn = tcp.createConnection(local, 12345, remote, 80) catch |err| {
        vga.print("  [FAIL] createConnection: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    if (conn.state == .CLOSED) {
        vga.print("  [OK] Connection created in CLOSED state\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Connection not in CLOSED state\n");
        fail_count += 1;
    }

    conn.state = .CLOSED;
}

fn testConnectionInitialState() void {
    vga.print("Test 3: Connection initial field values\n");
    const local = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 15 } };
    const remote = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 1 } };

    const conn = tcp.createConnection(local, 12346, remote, 80) catch |err| {
        vga.print("  [FAIL] createConnection: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    if (conn.local_port == 12346 and conn.remote_port == 80) {
        vga.print("  [OK] Ports set correctly\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Ports incorrect\n");
        fail_count += 1;
    }

    if (conn.recv_buffer_used == 0 and conn.send_buffer_used == 0) {
        vga.print("  [OK] Buffers start empty\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Buffers not empty on creation\n");
        fail_count += 1;
    }

    if (conn.send_una == conn.send_seq) {
        vga.print("  [OK] send_una == send_seq initially\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] send_una != send_seq\n");
        fail_count += 1;
    }

    conn.state = .CLOSED;
}

fn testCongestionWindowDefaults() void {
    vga.print("Test 4: Congestion control initial values\n");
    const local = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 15 } };
    const remote = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 1 } };

    const conn = tcp.createConnection(local, 12347, remote, 80) catch |err| {
        vga.print("  [FAIL] createConnection: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    if (conn.cwnd > 0) {
        vga.print("  [OK] cwnd initialized to ");
        printDec(conn.cwnd);
        vga.print("\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] cwnd is zero\n");
        fail_count += 1;
    }

    if (conn.ssthresh > 0) {
        vga.print("  [OK] ssthresh initialized to ");
        printDec(conn.ssthresh);
        vga.print("\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] ssthresh is zero\n");
        fail_count += 1;
    }

    if (conn.rto > 0) {
        vga.print("  [OK] RTO initialized to ");
        printDec(conn.rto);
        vga.print("\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] RTO is zero\n");
        fail_count += 1;
    }

    if (conn.bytes_in_flight == 0) {
        vga.print("  [OK] bytes_in_flight starts at 0\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] bytes_in_flight not 0\n");
        fail_count += 1;
    }

    if (conn.dup_ack_count == 0 and conn.retx_count == 0) {
        vga.print("  [OK] Counters start at 0\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Counters not 0\n");
        fail_count += 1;
    }

    conn.state = .CLOSED;
}

fn testSendOnClosedConnection() void {
    vga.print("Test 5: Send on non-ESTABLISHED connection\n");
    const local = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 15 } };
    const remote = ipv4.IPv4Address{ .octets = .{ 10, 0, 2, 1 } };

    const conn = tcp.createConnection(local, 12348, remote, 80) catch |err| {
        vga.print("  [FAIL] createConnection: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    _ = tcp.sendData(conn, "test data") catch {
        vga.print("  [OK] sendData on CLOSED connection correctly rejected\n");
        pass_count += 1;
        conn.state = .CLOSED;
        return;
    };
    vga.print("  [FAIL] sendData on CLOSED connection did not error\n");
    fail_count += 1;
    conn.state = .CLOSED;
}

fn testReceiveEmptyBuffer() void {
    vga.print("Test 6: Receive from empty buffer\n");
    const sock_id = tcp.listen(8081) catch |err| {
        vga.print("  [FAIL] listen: ");
        vga.print(@errorName(err));
        vga.print("\n");
        fail_count += 1;
        return;
    };

    // SAFETY: filled by the subsequent tcp.receive call
    var buf: [64]u8 = undefined;
    const n = tcp.receive(sock_id, &buf) catch |err| {
        vga.print("  [OK] Receive on listening socket returned error: ");
        vga.print(@errorName(err));
        vga.print("\n");
        pass_count += 1;
        tcp.close(sock_id) catch {};
        return;
    };

    if (n == 0) {
        vga.print("  [OK] Receive returned 0 bytes (empty)\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Received unexpected data\n");
        fail_count += 1;
    }
    tcp.close(sock_id) catch {};
}

fn testTickNoConnections() void {
    vga.print("Test 7: Tick with no active connections\n");
    tcp.tick();
    vga.print("  [OK] tick() completed without crash\n");
    pass_count += 1;
}

fn testMultipleListenSockets() void {
    vga.print("Test 8: Multiple listen sockets\n");
    // SAFETY: each element assigned by tcp.listen in the following loop
    var sockets: [4]usize = undefined;
    var opened: u32 = 0;

    for (0..4) |i| {
        sockets[i] = tcp.listen(@intCast(9000 + i)) catch break;
        opened += 1;
    }

    if (opened == 4) {
        vga.print("  [OK] Opened 4 listening sockets\n");
        pass_count += 1;
    } else {
        vga.print("  [FAIL] Only opened ");
        printDec(opened);
        vga.print(" of 4 sockets\n");
        fail_count += 1;
    }

    for (0..opened) |i| {
        tcp.close(sockets[i]) catch {};
    }

    if (opened >= 2 and sockets[0] != sockets[1]) {
        vga.print("  [OK] Each socket has unique ID\n");
        pass_count += 1;
    } else if (opened >= 2) {
        vga.print("  [FAIL] Duplicate socket IDs\n");
        fail_count += 1;
    }
}

fn printDec(value: u32) void {
    // SAFETY: filled by the following digit extraction loop
    var buffer: [10]u8 = undefined;
    var i: usize = 0;
    var v = value;

    if (v == 0) {
        vga.put_char('0');
        return;
    }

    while (v > 0) : (i += 1) {
        buffer[i] = @as(u8, @intCast(v % 10)) + '0';
        v /= 10;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}
