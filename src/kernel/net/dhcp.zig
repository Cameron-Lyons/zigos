// zlint-disable suppressed-errors
const socket = @import("socket.zig");
const ipv4 = @import("ipv4.zig");
const network = @import("network.zig");
const vga = @import("../drivers/vga.zig");
const timer = @import("../timer/timer.zig");

const DHCP_SERVER_PORT = 67;
const DHCP_CLIENT_PORT = 68;
const DHCP_MAGIC_COOKIE = 0x63825363;

const DHCPMessageType = enum(u8) {
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    DECLINE = 4,
    ACK = 5,
    NAK = 6,
    RELEASE = 7,
    INFORM = 8,
};

const DHCPOptionType = enum(u8) {
    PAD = 0,
    SUBNET_MASK = 1,
    ROUTER = 3,
    DNS_SERVER = 6,
    HOSTNAME = 12,
    DOMAIN_NAME = 15,
    REQUESTED_IP = 50,
    LEASE_TIME = 51,
    MESSAGE_TYPE = 53,
    SERVER_ID = 54,
    PARAM_REQUEST = 55,
    CLIENT_ID = 61,
    END = 255,
};

const DHCPHeader = extern struct {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: u32,
    yiaddr: u32,
    siaddr: u32,
    giaddr: u32,
    chaddr: [16]u8,
    sname: [64]u8,
    file: [128]u8,
    magic: u32,
};

const DHCPState = enum {
    INIT,
    SELECTING,
    REQUESTING,
    BOUND,
    RENEWING,
    REBINDING,
};

pub const DHCPClient = struct {
    state: DHCPState,
    transaction_id: u32,
    client_ip: ipv4.IPv4Address,
    server_ip: ipv4.IPv4Address,
    gateway_ip: ipv4.IPv4Address,
    subnet_mask: ipv4.IPv4Address,
    dns_server: ipv4.IPv4Address,
    lease_time: u32,
    renewal_time: u32,
    rebinding_time: u32,
    mac_address: [6]u8,

    pub fn init() DHCPClient {
        const rtl8139 = @import("../drivers/rtl8139.zig");
        const mac = rtl8139.getMACAddress() orelse [_]u8{0} ** 6;

        return DHCPClient{
            .state = .INIT,
            .transaction_id = @intCast(timer.getTicks()),
            .client_ip = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } },
            .server_ip = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } },
            .gateway_ip = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } },
            .subnet_mask = ipv4.IPv4Address{ .octets = .{ 255, 255, 255, 0 } },
            .dns_server = ipv4.IPv4Address{ .octets = .{ 8, 8, 8, 8 } },
            .lease_time = 0,
            .renewal_time = 0,
            .rebinding_time = 0,
            .mac_address = mac,
        };
    }

    pub fn discover(self: *DHCPClient) !void {
        const sock = try socket.createSocket(.DGRAM, .UDP);
        defer sock.close();

        const zero_ip = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } };
        try sock.bind(zero_ip, DHCP_CLIENT_PORT);

        // SAFETY: zeroed by the subsequent @memset call
        var packet: [548]u8 = undefined;
        @memset(&packet, 0);

        const header: *DHCPHeader = @ptrCast(@alignCast(&packet[0]));
        header.op = 1;
        header.htype = 1;
        header.hlen = 6;
        header.hops = 0;
        header.xid = @byteSwap(self.transaction_id);
        header.secs = 0;
        const discover_flags: u16 = 0x8000;
        header.flags = @byteSwap(discover_flags);
        header.ciaddr = 0;
        header.yiaddr = 0;
        header.siaddr = 0;
        header.giaddr = 0;
        @memcpy(header.chaddr[0..6], &self.mac_address);
        const discover_magic: u32 = DHCP_MAGIC_COOKIE;
        header.magic = @byteSwap(discover_magic);

        var options_offset: usize = 240;

        options_offset = self.addOption(&packet, options_offset, .MESSAGE_TYPE, &[_]u8{@intFromEnum(DHCPMessageType.DISCOVER)});

        const param_list = [_]u8{ 1, 3, 6, 15, 51, 54 };
        options_offset = self.addOption(&packet, options_offset, .PARAM_REQUEST, &param_list);

        packet[options_offset] = @intFromEnum(DHCPOptionType.END);
        options_offset += 1;

        const broadcast = ipv4.IPv4Address{ .octets = .{ 255, 255, 255, 255 } };
        try sock.sendTo(packet[0..options_offset], broadcast, DHCP_SERVER_PORT);

        self.state = .SELECTING;
        vga.print("DHCP DISCOVER sent\n");
    }

    pub fn handleOffer(self: *DHCPClient, data: []const u8) !void {
        if (data.len < @sizeOf(DHCPHeader)) {
            return error.InvalidPacket;
        }

        const header: *const DHCPHeader = @ptrCast(@alignCast(&data[0]));

        if (@byteSwap(header.xid) != self.transaction_id) {
            return error.InvalidTransaction;
        }

        const yiaddr_bytes: [4]u8 = @bitCast(header.yiaddr);
        self.client_ip = ipv4.IPv4Address{ .octets = yiaddr_bytes };

        self.parseOptions(data[240..]);

        self.state = .REQUESTING;
        try self.request();
    }

    fn request(self: *DHCPClient) !void {
        const sock = try socket.createSocket(.DGRAM, .UDP);
        defer sock.close();

        const zero_ip = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } };
        try sock.bind(zero_ip, DHCP_CLIENT_PORT);

        // SAFETY: zeroed by the subsequent @memset call
        var packet: [548]u8 = undefined;
        @memset(&packet, 0);

        const header: *DHCPHeader = @ptrCast(@alignCast(&packet[0]));
        header.op = 1;
        header.htype = 1;
        header.hlen = 6;
        header.hops = 0;
        header.xid = @byteSwap(self.transaction_id);
        header.secs = 0;
        const request_flags: u16 = 0x8000;
        header.flags = @byteSwap(request_flags);
        header.ciaddr = 0;
        header.yiaddr = 0;
        header.siaddr = 0;
        header.giaddr = 0;
        @memcpy(header.chaddr[0..6], &self.mac_address);
        const request_magic: u32 = DHCP_MAGIC_COOKIE;
        header.magic = @byteSwap(request_magic);

        var options_offset: usize = 240;

        options_offset = self.addOption(&packet, options_offset, .MESSAGE_TYPE, &[_]u8{@intFromEnum(DHCPMessageType.REQUEST)});

        const client_ip_u32: u32 = @bitCast(self.client_ip.octets);
        const requested_ip: [4]u8 = @bitCast(client_ip_u32);
        options_offset = self.addOption(&packet, options_offset, .REQUESTED_IP, &requested_ip);

        const req_server_ip_u32: u32 = @bitCast(self.server_ip.octets);
        const server_id: [4]u8 = @bitCast(req_server_ip_u32);
        options_offset = self.addOption(&packet, options_offset, .SERVER_ID, &server_id);

        packet[options_offset] = @intFromEnum(DHCPOptionType.END);
        options_offset += 1;

        const broadcast = ipv4.IPv4Address{ .octets = .{ 255, 255, 255, 255 } };
        try sock.sendTo(packet[0..options_offset], broadcast, DHCP_SERVER_PORT);

        vga.print("DHCP REQUEST sent\n");
    }

    pub fn handleAck(self: *DHCPClient, data: []const u8) !void {
        if (data.len < @sizeOf(DHCPHeader)) {
            return error.InvalidPacket;
        }

        const header: *const DHCPHeader = @ptrCast(@alignCast(&data[0]));

        if (@byteSwap(header.xid) != self.transaction_id) {
            return error.InvalidTransaction;
        }

        self.parseOptions(data[240..]);

        network.setLocalIP(self.client_ip);
        network.setGateway(self.gateway_ip);
        network.setNetmask(self.subnet_mask);

        const dns = @import("dns.zig");
        dns.setDNSServer(self.dns_server);

        self.state = .BOUND;

        vga.print("DHCP configuration received:\n");
        vga.print("  IP: ");
        network.printIPv4(self.client_ip);
        vga.print("\n  Gateway: ");
        network.printIPv4(self.gateway_ip);
        vga.print("\n  Netmask: ");
        network.printIPv4(self.subnet_mask);
        vga.print("\n  DNS: ");
        network.printIPv4(self.dns_server);
        vga.print("\n  Lease time: ");
        printNumber(self.lease_time);
        vga.print(" seconds\n");
    }

    fn parseOptions(self: *DHCPClient, options: []const u8) void {
        var i: usize = 0;

        while (i < options.len) {
            const opt_type = options[i];
            if (opt_type == @intFromEnum(DHCPOptionType.END)) {
                break;
            }
            if (opt_type == @intFromEnum(DHCPOptionType.PAD)) {
                i += 1;
                continue;
            }

            i += 1;
            if (i >= options.len) break;

            const opt_len = options[i];
            i += 1;

            if (i + opt_len > options.len) break;

            const opt_type_enum: DHCPOptionType = @enumFromInt(opt_type);
            switch (opt_type_enum) {
                .SUBNET_MASK => {
                    if (opt_len == 4) {
                        self.subnet_mask = ipv4.IPv4Address{ .octets = .{
                            options[i], options[i + 1], options[i + 2], options[i + 3]
                        } };
                    }
                },
                .ROUTER => {
                    if (opt_len >= 4) {
                        self.gateway_ip = ipv4.IPv4Address{ .octets = .{
                            options[i], options[i + 1], options[i + 2], options[i + 3]
                        } };
                    }
                },
                .DNS_SERVER => {
                    if (opt_len >= 4) {
                        self.dns_server = ipv4.IPv4Address{ .octets = .{
                            options[i], options[i + 1], options[i + 2], options[i + 3]
                        } };
                    }
                },
                .LEASE_TIME => {
                    if (opt_len == 4) {
                        const b0: u32 = options[i];
                        const b1: u32 = options[i + 1];
                        const b2: u32 = options[i + 2];
                        self.lease_time = (b0 << 24) |
                                         (b1 << 16) |
                                         (b2 << 8) |
                                         options[i + 3];
                        self.renewal_time = self.lease_time / 2;
                        self.rebinding_time = (self.lease_time * 7) / 8;
                    }
                },
                .SERVER_ID => {
                    if (opt_len == 4) {
                        self.server_ip = ipv4.IPv4Address{ .octets = .{
                            options[i], options[i + 1], options[i + 2], options[i + 3]
                        } };
                    }
                },
                else => {},
            }

            i += opt_len;
        }
    }

    fn addOption(self: *DHCPClient, packet: []u8, offset: usize, opt_type: DHCPOptionType, data: []const u8) usize {
        _ = self;
        packet[offset] = @intFromEnum(opt_type);
        packet[offset + 1] = @intCast(data.len);
        @memcpy(packet[offset + 2..offset + 2 + data.len], data);
        return offset + 2 + data.len;
    }

    pub fn release(self: *DHCPClient) !void {
        if (self.state != .BOUND) {
            return;
        }

        const sock = try socket.createSocket(.DGRAM, .UDP);
        defer sock.close();

        try sock.bind(self.client_ip, DHCP_CLIENT_PORT);

        // SAFETY: zeroed by the subsequent @memset call
        var packet: [548]u8 = undefined;
        @memset(&packet, 0);

        const header: *DHCPHeader = @ptrCast(@alignCast(&packet[0]));
        header.op = 1;
        header.htype = 1;
        header.hlen = 6;
        header.hops = 0;
        header.xid = @byteSwap(self.transaction_id);
        header.secs = 0;
        header.flags = 0;
        header.ciaddr = @bitCast(self.client_ip.octets);
        header.yiaddr = 0;
        header.siaddr = 0;
        header.giaddr = 0;
        @memcpy(header.chaddr[0..6], &self.mac_address);
        const release_magic: u32 = DHCP_MAGIC_COOKIE;
        header.magic = @byteSwap(release_magic);

        var options_offset: usize = 240;

        options_offset = self.addOption(&packet, options_offset, .MESSAGE_TYPE, &[_]u8{@intFromEnum(DHCPMessageType.RELEASE)});

        const rel_server_ip_u32: u32 = @bitCast(self.server_ip.octets);
        const server_id: [4]u8 = @bitCast(rel_server_ip_u32);
        options_offset = self.addOption(&packet, options_offset, .SERVER_ID, &server_id);

        packet[options_offset] = @intFromEnum(DHCPOptionType.END);
        options_offset += 1;

        try sock.sendTo(packet[0..options_offset], self.server_ip, DHCP_SERVER_PORT);

        self.state = .INIT;
        vga.print("DHCP RELEASE sent\n");
    }
};

var dhcp_client: ?DHCPClient = null;

pub fn init() void {
    dhcp_client = DHCPClient.init();
    vga.print("DHCP client initialized\n");
}

pub fn requestAddress() !void {
    if (dhcp_client) |*client| {
        try client.discover();
    } else {
        return error.NotInitialized;
    }
}

pub fn releaseAddress() !void {
    if (dhcp_client) |*client| {
        try client.release();
    } else {
        return error.NotInitialized;
    }
}

pub fn handlePacket(data: []const u8) void {
    if (dhcp_client) |*client| {
        if (data.len < @sizeOf(DHCPHeader)) {
            return;
        }

        const header: *const DHCPHeader = @ptrCast(@alignCast(&data[0]));
        if (header.op != 2) {
            return;
        }

        var msg_type: ?DHCPMessageType = null;
        var i: usize = 240;
        while (i < data.len) {
            const opt_type = data[i];
            if (opt_type == @intFromEnum(DHCPOptionType.END)) {
                break;
            }
            if (opt_type == @intFromEnum(DHCPOptionType.PAD)) {
                i += 1;
                continue;
            }

            i += 1;
            if (i >= data.len) break;

            const opt_len = data[i];
            i += 1;

            if (i + opt_len > data.len) break;

            if (opt_type == @intFromEnum(DHCPOptionType.MESSAGE_TYPE) and opt_len == 1) {
                msg_type = @enumFromInt(data[i]);
                break;
            }

            i += opt_len;
        }

        if (msg_type) |mt| {
            switch (mt) {
                .OFFER => {
                    if (client.state == .SELECTING) {
                        client.handleOffer(data) catch {};
                    }
                },
                .ACK => {
                    if (client.state == .REQUESTING) {
                        client.handleAck(data) catch {};
                    }
                },
                .NAK => {
                    vga.print("DHCP NAK received\n");
                    client.state = .INIT;
                },
                else => {},
            }
        }
    }
}

fn printNumber(num: u32) void {
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