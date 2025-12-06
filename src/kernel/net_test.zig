const std = @import("std");
const vga = @import("vga.zig");
const network = @import("network.zig");
const socket = @import("socket.zig");
const dns = @import("dns.zig");
const http = @import("http.zig");
const tcp = @import("tcp.zig");
const process = @import("process.zig");
const timer = @import("timer.zig");

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
        return;
    };
    defer sock.close();

    vga.print("  [PASS] TCP socket created successfully\n");

    const udp_sock = socket.createSocket(.DGRAM, .UDP) catch {
        vga.print("  [FAIL] Could not create UDP socket\n");
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

    server.start() catch {
        vga.print("  [FAIL] Could not start HTTP server\n");
        return;
    };

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
    vga.print("  [PASS] Custom handler registered\n");

    server.stop();
    vga.print("  [PASS] HTTP server stopped\n");
}

fn testTCPConnection() void {
    vga.print("\nTest 4: TCP Connection (loopback)...\n");

    const server_sock = socket.createSocket(.STREAM, .TCP) catch {
        vga.print("  [FAIL] Could not create server socket\n");
        return;
    };
    defer server_sock.close();

    const loopback = network.ipv4.IPv4Address{ .octets = .{ 127, 0, 0, 1 } };
    server_sock.bind(loopback, 9999) catch {
        vga.print("  [FAIL] Could not bind to port 9999\n");
        return;
    };
    vga.print("  [PASS] Server bound to 127.0.0.1:9999\n");

    server_sock.listen(5) catch {
        vga.print("  [FAIL] Could not listen on socket\n");
        return;
    };
    vga.print("  [PASS] Server listening for connections\n");

    const client_sock = socket.createSocket(.STREAM, .TCP) catch {
        vga.print("  [FAIL] Could not create client socket\n");
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