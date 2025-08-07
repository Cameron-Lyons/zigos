const std = @import("std");
const socket = @import("socket.zig");
const memory = @import("memory.zig");
const vga = @import("vga.zig");
const process = @import("process.zig");
const ipv4 = @import("ipv4.zig");

const HTTP_PORT = 80;
const MAX_REQUEST_SIZE = 2048;
const MAX_RESPONSE_SIZE = 4096;

const HTTPMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    UNKNOWN,
};

const HTTPRequest = struct {
    method: HTTPMethod,
    path: []const u8,
    version: []const u8,
    headers: []Header,
    body: []const u8,
    
    const Header = struct {
        name: []const u8,
        value: []const u8,
    };
};

const HTTPResponse = struct {
    status_code: u16,
    status_text: []const u8,
    headers: []const Header,
    body: []const u8,
    
    const Header = struct {
        name: []const u8,
        value: []const u8,
    };
};

pub const HTTPServer = struct {
    listen_socket: ?*socket.Socket,
    port: u16,
    running: bool,
    handler: ?*const fn (*const HTTPRequest) HTTPResponse,
    
    pub fn init(port: u16) HTTPServer {
        return HTTPServer{
            .listen_socket = null,
            .port = port,
            .running = false,
            .handler = null,
        };
    }
    
    pub fn setHandler(self: *HTTPServer, handler: *const fn (*const HTTPRequest) HTTPResponse) void {
        self.handler = handler;
    }
    
    pub fn start(self: *HTTPServer) !void {
        self.listen_socket = try socket.createSocket(.STREAM, .TCP);
        const local_addr = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } };
        try self.listen_socket.?.bind(local_addr, self.port);
        try self.listen_socket.?.listen(16);
        
        self.running = true;
        vga.print("HTTP server listening on port ");
        printNumber(self.port);
        vga.print("\n");
    }
    
    pub fn handleConnections(self: *HTTPServer) void {
        while (self.running) {
            const client = self.listen_socket.?.accept() catch {
                process.yield();
                continue;
            };
            
            self.handleClient(client);
            client.close();
        }
    }
    
    fn handleClient(self: *HTTPServer, client: *socket.Socket) void {
        var request_buffer: [MAX_REQUEST_SIZE]u8 = undefined;
        const bytes_read = client.recv(&request_buffer) catch {
            return;
        };
        
        if (bytes_read == 0) {
            return;
        }
        
        const request_data = request_buffer[0..bytes_read];
        const request = parseRequest(request_data) catch {
            self.sendErrorResponse(client, 400, "Bad Request");
            return;
        };
        
        var response: HTTPResponse = undefined;
        if (self.handler) |handler| {
            response = handler(&request);
        } else {
            response = defaultHandler(&request);
        }
        
        self.sendResponse(client, &response);
    }
    
    fn parseRequest(data: []const u8) !HTTPRequest {
        var request = HTTPRequest{
            .method = .UNKNOWN,
            .path = &[_]u8{},
            .version = &[_]u8{},
            .headers = &[_]HTTPRequest.Header{},
            .body = &[_]u8{},
        };
        
        var i: usize = 0;
        
        const method_end = findChar(data, i, ' ') orelse return error.InvalidRequest;
        const method_str = data[i..method_end];
        request.method = parseMethod(method_str);
        i = method_end + 1;
        
        const path_end = findChar(data, i, ' ') orelse return error.InvalidRequest;
        request.path = data[i..path_end];
        i = path_end + 1;
        
        const version_end = findString(data, i, "\r\n") orelse return error.InvalidRequest;
        request.version = data[i..version_end];
        i = version_end + 2;
        
        const headers_end = findString(data, i, "\r\n\r\n") orelse i + findString(data, i, "\n\n").?;
        i = headers_end + 4;
        
        if (i < data.len) {
            request.body = data[i..];
        }
        
        return request;
    }
    
    fn parseMethod(method: []const u8) HTTPMethod {
        if (streq(method, "GET")) return .GET;
        if (streq(method, "POST")) return .POST;
        if (streq(method, "PUT")) return .PUT;
        if (streq(method, "DELETE")) return .DELETE;
        if (streq(method, "HEAD")) return .HEAD;
        if (streq(method, "OPTIONS")) return .OPTIONS;
        return .UNKNOWN;
    }
    
    fn defaultHandler(request: *const HTTPRequest) HTTPResponse {
        _ = request;
        const html_body = 
            \\<!DOCTYPE html>
            \\<html>
            \\<head>
            \\    <title>ZigOS HTTP Server</title>
            \\</head>
            \\<body>
            \\    <h1>Welcome to ZigOS HTTP Server!</h1>
            \\    <p>This is a simple HTTP server running on ZigOS.</p>
            \\    <p>System uptime: <span id="uptime">calculating...</span></p>
            \\</body>
            \\</html>
        ;
        
        const headers = [_]HTTPResponse.Header{
                .{ .name = "Content-Type", .value = "text/html" },
                .{ .name = "Server", .value = "ZigOS/1.0" },
        };
        return HTTPResponse{
            .status_code = 200,
            .status_text = "OK",
            .headers = &headers,
            .body = html_body,
        };
    }
    
    fn sendResponse(self: *HTTPServer, client: *socket.Socket, response: *const HTTPResponse) void {
        _ = self;
        var response_buffer: [MAX_RESPONSE_SIZE]u8 = undefined;
        var offset: usize = 0;
        
        offset += formatString(&response_buffer, offset, "HTTP/1.1 ");
        offset += formatNumber(&response_buffer, offset, response.status_code);
        offset += formatString(&response_buffer, offset, " ");
        offset += formatString(&response_buffer, offset, response.status_text);
        offset += formatString(&response_buffer, offset, "\r\n");
        
        for (response.headers) |header| {
            offset += formatString(&response_buffer, offset, header.name);
            offset += formatString(&response_buffer, offset, ": ");
            offset += formatString(&response_buffer, offset, header.value);
            offset += formatString(&response_buffer, offset, "\r\n");
        }
        
        offset += formatString(&response_buffer, offset, "Content-Length: ");
        offset += formatNumber(&response_buffer, offset, response.body.len);
        offset += formatString(&response_buffer, offset, "\r\n");
        offset += formatString(&response_buffer, offset, "\r\n");
        
        offset += formatString(&response_buffer, offset, response.body);
        
        _ = client.send(response_buffer[0..offset]) catch {};
    }
    
    fn sendErrorResponse(self: *HTTPServer, client: *socket.Socket, code: u16, message: []const u8) void {
        const headers = [_]HTTPResponse.Header{
                .{ .name = "Content-Type", .value = "text/plain" },
                .{ .name = "Server", .value = "ZigOS/1.0" },
        };
        const response = HTTPResponse{
            .status_code = code,
            .status_text = message,
            .headers = &headers,
            .body = message,
        };
        self.sendResponse(client, &response);
    }
    
    pub fn stop(self: *HTTPServer) void {
        self.running = false;
        if (self.listen_socket) |sock| {
            sock.close();
        }
    }
};

fn findChar(data: []const u8, start: usize, char: u8) ?usize {
    var i = start;
    while (i < data.len) : (i += 1) {
        if (data[i] == char) {
            return i;
        }
    }
    return null;
}

fn findString(data: []const u8, start: usize, needle: []const u8) ?usize {
    if (start + needle.len > data.len) {
        return null;
    }
    
    var i = start;
    while (i <= data.len - needle.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |c, j| {
            if (data[i + j] != c) {
                match = false;
                break;
            }
        }
        if (match) {
            return i;
        }
    }
    return null;
}

fn streq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (ac != bc) return false;
    }
    return true;
}

fn formatString(buffer: []u8, offset: usize, str: []const u8) usize {
    const len = @min(str.len, buffer.len - offset);
    @memcpy(buffer[offset..offset + len], str[0..len]);
    return len;
}

fn formatNumber(buffer: []u8, offset: usize, num: usize) usize {
    if (num == 0) {
        if (offset < buffer.len) {
            buffer[offset] = '0';
            return 1;
        }
        return 0;
    }
    
    var temp: [20]u8 = undefined;
    var temp_len: usize = 0;
    var n = num;
    
    while (n > 0) : (n /= 10) {
        temp[temp_len] = @intCast('0' + (n % 10));
        temp_len += 1;
    }
    
    var i: usize = 0;
    while (i < temp_len and offset + i < buffer.len) : (i += 1) {
        buffer[offset + i] = temp[temp_len - 1 - i];
    }
    
    return i;
}

fn printNumber(num: usize) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }
    
    var digits: [20]u8 = undefined;
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