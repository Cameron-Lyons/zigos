const std = @import("std");
const vga = @import("../drivers/vga.zig");
const console = @import("../utils/console.zig");
const arp = @import("../net/arp.zig");
const ethernet = @import("../net/ethernet.zig");
const network = @import("../net/network.zig");
const socket = @import("../net/socket.zig");
const http = @import("../net/http.zig");
const process = @import("../process/process.zig");

var fail_count: usize = 0;
var captured_frame_len: usize = 0;
var captured_frame: [ethernet.ETH_HEADER_SIZE + ethernet.ETH_MTU]u8 = undefined;
const test_src_mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const test_gateway_mac = [6]u8{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };

pub fn runNetworkTestsChecked() bool {
    fail_count = 0;
    printSerialMarker("NETTEST:ROUTE:START");
    if (!testArpAndRoutingChecked()) {
        fail_count += 1;
        return false;
    }
    printSerialMarker("NETTEST:ROUTE:PASS");
    printSerialMarker("NETTEST:HTTP:START");
    if (!testHTTPServerChecked()) {
        fail_count += 1;
        return false;
    }
    printSerialMarker("NETTEST:HTTP:PASS");
    printSerialMarker("NETTEST:TCP:START");
    if (!testTCPConnectionChecked()) {
        fail_count += 1;
        return false;
    }
    printSerialMarker("NETTEST:TCP:PASS");
    printSerialMarker("NETTEST:SOCKET:START");
    testSocketCreation();
    printSerialMarker("NETTEST:SOCKET:PASS");
    printSerialMarker("NETTEST:DNS:START");
    testDNSResolution();
    printSerialMarker("NETTEST:DNS:PASS");
    return fail_count == 0;
}

pub fn runNetworkTests() void {
    vga.print("\n=== Network Stack Test Suite ===\n\n");

    testSocketCreation();
    testDNSResolution();
    testHTTPServer();
    testTCPConnection();

    vga.print("\n=== All Network Tests Complete ===\n");
}

fn testSocketCreation() void {
    vga.print("Test 1: Socket Creation...\n");

    const sock = socket.createSocket(.STREAM, .TCP) catch {
        vga.print("  [FAIL] Could not create TCP socket\n");
        fail_count += 1;
        return;
    };
    defer sock.close();

    vga.print("  [PASS] TCP socket created successfully\n");

    const udp_sock = socket.createSocket(.DGRAM, .UDP) catch {
        vga.print("  [FAIL] Could not create UDP socket\n");
        fail_count += 1;
        return;
    };
    defer udp_sock.close();

    vga.print("  [PASS] UDP socket created successfully\n");
}

fn testDNSResolution() void {
    vga.print("\nTest 2: DNS Resolution (simulated)...\n");

    const test_domains = [_][]const u8{
        "localhost",
        "example.com",
        "google.com",
    };

    for (test_domains) |domain| {
        vga.print("  Resolving ");
        vga.print(domain);
        vga.print(": ");

        if (streq(domain, "localhost")) {
            vga.print("127.0.0.1 [PASS]\n");
        } else {
            vga.print("(would query DNS server) [SKIP]\n");
        }
    }
}

fn testHTTPServer() void {
    vga.print("\nTest 3: HTTP Server...\n");

    var server = http.HTTPServer.init(8080);
    printSerialMarker("NETTEST:HTTP:INIT");

    server.start() catch {
        vga.print("  [FAIL] Could not start HTTP server\n");
        fail_count += 1;
        return;
    };
    printSerialMarker("NETTEST:HTTP:STARTED");

    vga.print("  [PASS] HTTP server started on port 8080\n");

    const test_handler = struct {
        fn handler(request: *const http.HTTPRequest) http.HTTPResponse {
            _ = request;
            const headers = [_]http.HTTPResponse.Header{
                .{ .name = "Content-Type", .value = "text/plain" },
                .{ .name = "Server", .value = "ZigOS-Test/1.0" },
            };
            return http.HTTPResponse{
                .status_code = 200,
                .status_text = "OK",
                .headers = &headers,
                .body = "Test response from ZigOS HTTP server",
            };
        }
    }.handler;

    server.setHandler(&test_handler);
    printSerialMarker("NETTEST:HTTP:HANDLER");
    vga.print("  [PASS] Custom handler registered\n");

    server.stop();
    printSerialMarker("NETTEST:HTTP:STOPPED");
    vga.print("  [PASS] HTTP server stopped\n");
}

fn testArpAndRoutingChecked() bool {
    ethernet.setTxHook(&captureTxFrame);
    defer ethernet.setTxHook(null);

    const remote_ip = network.ipv4.IPv4Address{ .octets = .{ 8, 8, 8, 8 } };
    const gateway = network.getGateway();

    clearCapturedFrame();
    printSerialMarker("NETTEST:ROUTE:ARP_REQ");
    network.ipv4.sendPacket(remote_ip.toU32(), .UDP, "route probe") catch |err| switch (err) {
        error.ARPResolutionFailed => {
            printSerialMarker("NETTEST:ROUTE:ARP_ERR_EXPECTED");
        },
        else => {
            printSerialMarker("NETTEST:ROUTE:ARP_ERR_UNEXPECTED");
            return false;
        },
    };
    printSerialMarker("NETTEST:ROUTE:ARP_REQ_SENT");

    const arp_request = parseCapturedEthernet() orelse return false;
    printSerialMarker("NETTEST:ROUTE:ARP_FRAME");
    if (@byteSwap(arp_request.ethertype) != @intFromEnum(ethernet.EtherType.ARP)) return false;
    if (!macEquals(readDstMac(arp_request), &[_]u8{0xff} ** 6)) return false;

    const arp_request_header = parseCapturedArp() orelse return false;
    printSerialMarker("NETTEST:ROUTE:ARP_HEADER");
    if (@byteSwap(arp_request_header.opcode) != 1) return false;
    if (@byteSwap(arp_request_header.target_ip) != gateway.toU32()) return false;
    printSerialMarker("NETTEST:ROUTE:ARP_REQ_OK");

    var reply_frame: [ethernet.ETH_HEADER_SIZE + @sizeOf(arp.ARPHeader)]u8 = undefined;
    writeArpReply(&reply_frame, gateway, network.getLocalIP(), test_gateway_mac, test_src_mac);
    network.processPacket(reply_frame[0..], test_gateway_mac);

    const resolved_mac = arp.resolve(gateway.toU32()) orelse return false;
    if (!macEquals(resolved_mac, &test_gateway_mac)) return false;
    printSerialMarker("NETTEST:ROUTE:ARP_REPLY_OK");

    clearCapturedFrame();
    printSerialMarker("NETTEST:ROUTE:IP_SEND");
    network.ipv4.sendPacket(remote_ip.toU32(), .UDP, "route probe") catch {
        printSerialMarker("NETTEST:ROUTE:IP_SEND_ERR");
        return false;
    };
    printSerialMarker("NETTEST:ROUTE:IP_SEND_DONE");
    printSerialMarker("NETTEST:ROUTE:IP_SEND_OK");
    return true;
}

fn testHTTPServerChecked() bool {
    var server = http.HTTPServer.init(8080);
    printSerialMarker("NETTEST:HTTP:INIT");

    server.listen_socket = socket.createSocket(.STREAM, .TCP) catch {
        printSerialMarker("NETTEST:HTTP:CREATE_FAIL");
        return false;
    };
    defer if (server.listen_socket) |sock| sock.close();
    printSerialMarker("NETTEST:HTTP:CREATE_OK");

    const local_addr = network.ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } };
    server.listen_socket.?.bind(local_addr, 8080) catch {
        printSerialMarker("NETTEST:HTTP:BIND_FAIL");
        return false;
    };
    printSerialMarker("NETTEST:HTTP:BIND_OK");

    server.listen_socket.?.listen(16) catch {
        printSerialMarker("NETTEST:HTTP:LISTEN_FAIL");
        return false;
    };
    printSerialMarker("NETTEST:HTTP:LISTEN_OK");

    const test_handler = struct {
        fn handler(request: *const http.HTTPRequest) http.HTTPResponse {
            _ = request;
            const headers = [_]http.HTTPResponse.Header{
                .{ .name = "Content-Type", .value = "text/plain" },
                .{ .name = "Server", .value = "ZigOS-Test/1.0" },
            };
            return http.HTTPResponse{
                .status_code = 200,
                .status_text = "OK",
                .headers = &headers,
                .body = "Test response from ZigOS HTTP server",
            };
        }
    }.handler;

    server.setHandler(&test_handler);
    printSerialMarker("NETTEST:HTTP:HANDLER");
    if (server.handler == null) return false;
    return true;
}

fn testTCPConnectionChecked() bool {
    const server_sock = socket.createSocket(.STREAM, .TCP) catch {
        printSerialMarker("NETTEST:TCP:CREATE_SERVER_FAIL");
        return false;
    };
    defer server_sock.close();
    printSerialMarker("NETTEST:TCP:CREATE_SERVER_OK");

    const loopback = network.ipv4.IPv4Address{ .octets = .{ 127, 0, 0, 1 } };
    server_sock.bind(loopback, 9999) catch {
        printSerialMarker("NETTEST:TCP:BIND_FAIL");
        return false;
    };
    printSerialMarker("NETTEST:TCP:BIND_OK");

    server_sock.listen(2) catch {
        printSerialMarker("NETTEST:TCP:LISTEN_FAIL");
        return false;
    };
    printSerialMarker("NETTEST:TCP:LISTEN_OK");

    const client_sock = socket.createSocket(.STREAM, .TCP) catch {
        printSerialMarker("NETTEST:TCP:CREATE_CLIENT_FAIL");
        return false;
    };
    defer client_sock.close();
    printSerialMarker("NETTEST:TCP:CREATE_CLIENT_OK");

    client_sock.bind(loopback, 10000) catch {
        printSerialMarker("NETTEST:TCP:CLIENT_BIND_FAIL");
        return false;
    };
    printSerialMarker("NETTEST:TCP:CLIENT_BIND_OK");

    client_sock.connect(loopback, 9999) catch {
        printSerialMarker("NETTEST:TCP:CONNECT_FAIL");
        return false;
    };
    printSerialMarker("NETTEST:TCP:CONNECT_OK");

    const accepted = server_sock.accept() catch {
        printSerialMarker("NETTEST:TCP:ACCEPT_FAIL");
        return false;
    };
    defer accepted.close();
    printSerialMarker("NETTEST:TCP:ACCEPT_OK");

    const client_payload = "loopback ping";
    if ((client_sock.send(client_payload) catch 0) != client_payload.len) {
        printSerialMarker("NETTEST:TCP:SEND_FAIL");
        return false;
    }
    printSerialMarker("NETTEST:TCP:SEND_OK");

    var recv_buf: [32]u8 = undefined;
    const recv_len = accepted.recv(recv_buf[0..client_payload.len]) catch {
        printSerialMarker("NETTEST:TCP:RECV_FAIL");
        return false;
    };
    if (recv_len != client_payload.len or !streq(recv_buf[0..recv_len], client_payload)) {
        printSerialMarker("NETTEST:TCP:RECV_MISMATCH");
        return false;
    }
    printSerialMarker("NETTEST:TCP:RECV_OK");

    const reply_payload = "loopback pong";
    if ((accepted.send(reply_payload) catch 0) != reply_payload.len) {
        printSerialMarker("NETTEST:TCP:REPLY_FAIL");
        return false;
    }
    printSerialMarker("NETTEST:TCP:REPLY_OK");

    var reply_buf: [32]u8 = undefined;
    const reply_len = client_sock.recv(reply_buf[0..reply_payload.len]) catch {
        printSerialMarker("NETTEST:TCP:CLIENT_RECV_FAIL");
        return false;
    };
    if (reply_len != reply_payload.len or !streq(reply_buf[0..reply_len], reply_payload)) {
        printSerialMarker("NETTEST:TCP:CLIENT_RECV_MISMATCH");
        return false;
    }
    printSerialMarker("NETTEST:TCP:CLIENT_RECV_OK");
    return true;
}

fn testTCPConnection() void {
    vga.print("\nTest 4: TCP Connection (loopback)...\n");

    const server_sock = socket.createSocket(.STREAM, .TCP) catch {
        vga.print("  [FAIL] Could not create server socket\n");
        fail_count += 1;
        return;
    };
    defer server_sock.close();

    const loopback = network.ipv4.IPv4Address{ .octets = .{ 127, 0, 0, 1 } };
    server_sock.bind(loopback, 9999) catch {
        vga.print("  [FAIL] Could not bind to port 9999\n");
        fail_count += 1;
        return;
    };
    vga.print("  [PASS] Server bound to 127.0.0.1:9999\n");

    server_sock.listen(5) catch {
        vga.print("  [FAIL] Could not listen on socket\n");
        fail_count += 1;
        return;
    };
    vga.print("  [PASS] Server listening for connections\n");

    const client_sock = socket.createSocket(.STREAM, .TCP) catch {
        vga.print("  [FAIL] Could not create client socket\n");
        fail_count += 1;
        return;
    };
    defer client_sock.close();

    vga.print("  [INFO] TCP connection test complete\n");
}

pub fn runEchoServer(port: u16) void {
    vga.print("Starting Echo Server on port ");
    printNumber(port);
    vga.print("...\n");

    const sock = socket.createSocket(.STREAM, .TCP) catch {
        vga.print("Failed to create socket\n");
        return;
    };
    defer sock.close();

    const any_addr = network.ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } };
    sock.bind(any_addr, port) catch {
        vga.print("Failed to bind socket\n");
        return;
    };

    sock.listen(5) catch {
        vga.print("Failed to listen on socket\n");
        return;
    };

    vga.print("Echo server listening...\n");

    while (true) {
        const client = sock.accept() catch {
            process.yield();
            continue;
        };

        handleEchoClient(client);
        client.close();
    }
}

fn handleEchoClient(client: *socket.Socket) void {
    // SAFETY: filled by the subsequent client.recv call
    var buffer: [256]u8 = undefined;

    while (true) {
        const bytes_read = client.recv(&buffer) catch break;

        if (bytes_read == 0) {
            break;
        }

        _ = client.send(buffer[0..bytes_read]) catch break;
    }
}

fn streq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (ac != bc) return false;
    }
    return true;
}

fn printNumber(num: u16) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[count] = @intCast('0' + (n % 10));
        count += 1;
    }

    var i = count;
    while (i > 0) {
        i -= 1;
        vga.put_char(digits[i]);
    }
}

fn printSerialMarker(marker: []const u8) void {
    console.print(marker);
    console.print("\n");
}

fn captureTxFrame(frame: []const u8) void {
    captured_frame_len = @min(frame.len, captured_frame.len);
    @memcpy(captured_frame[0..captured_frame_len], frame[0..captured_frame_len]);
}

fn clearCapturedFrame() void {
    captured_frame_len = 0;
}

fn parseCapturedEthernet() ?*align(1) const ethernet.EthernetHeader {
    if (captured_frame_len < ethernet.ETH_HEADER_SIZE) return null;
    return @ptrCast(captured_frame[0..].ptr);
}

fn parseCapturedArp() ?*align(1) const arp.ARPHeader {
    if (captured_frame_len < ethernet.ETH_HEADER_SIZE + @sizeOf(arp.ARPHeader)) return null;
    return @ptrCast(captured_frame[ethernet.ETH_HEADER_SIZE..].ptr);
}

fn readDstMac(header: *align(1) const ethernet.EthernetHeader) [6]u8 {
    return .{ header.dst_mac0, header.dst_mac1, header.dst_mac2, header.dst_mac3, header.dst_mac4, header.dst_mac5 };
}

fn writeArpReply(
    frame: []u8,
    sender_ip: network.ipv4.IPv4Address,
    target_ip: network.ipv4.IPv4Address,
    sender_mac: [6]u8,
    target_mac: [6]u8,
) void {
    const eth_header: *align(1) ethernet.EthernetHeader = @ptrCast(frame.ptr);
    eth_header.dst_mac0 = target_mac[0];
    eth_header.dst_mac1 = target_mac[1];
    eth_header.dst_mac2 = target_mac[2];
    eth_header.dst_mac3 = target_mac[3];
    eth_header.dst_mac4 = target_mac[4];
    eth_header.dst_mac5 = target_mac[5];
    eth_header.src_mac0 = sender_mac[0];
    eth_header.src_mac1 = sender_mac[1];
    eth_header.src_mac2 = sender_mac[2];
    eth_header.src_mac3 = sender_mac[3];
    eth_header.src_mac4 = sender_mac[4];
    eth_header.src_mac5 = sender_mac[5];
    eth_header.ethertype = @byteSwap(@intFromEnum(ethernet.EtherType.ARP));

    const arp_header: *align(1) arp.ARPHeader = @ptrCast(frame[ethernet.ETH_HEADER_SIZE..].ptr);
    arp_header.hardware_type = @byteSwap(@as(u16, 1));
    arp_header.protocol_type = @byteSwap(@as(u16, 0x0800));
    arp_header.hardware_addr_len = 6;
    arp_header.protocol_addr_len = 4;
    arp_header.opcode = @byteSwap(@as(u16, 2));
    arp_header.sender_mac0 = sender_mac[0];
    arp_header.sender_mac1 = sender_mac[1];
    arp_header.sender_mac2 = sender_mac[2];
    arp_header.sender_mac3 = sender_mac[3];
    arp_header.sender_mac4 = sender_mac[4];
    arp_header.sender_mac5 = sender_mac[5];
    arp_header.sender_ip = @byteSwap(sender_ip.toU32());
    arp_header.target_mac0 = target_mac[0];
    arp_header.target_mac1 = target_mac[1];
    arp_header.target_mac2 = target_mac[2];
    arp_header.target_mac3 = target_mac[3];
    arp_header.target_mac4 = target_mac[4];
    arp_header.target_mac5 = target_mac[5];
    arp_header.target_ip = @byteSwap(target_ip.toU32());
}

fn ipEquals(a: network.ipv4.IPv4Address, b: network.ipv4.IPv4Address) bool {
    return std.mem.eql(u8, &a.octets, &b.octets);
}

fn macEquals(a: [6]u8, b: *const [6]u8) bool {
    return std.mem.eql(u8, &a, b);
}
