const std = @import("std");
const ipv4 = @import("ipv4.zig");
const network = @import("network.zig");
const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");

const MAX_ROUTES = 32;
const MAX_ARP_ENTRIES = 64;

pub const RouteFlags = struct {
    const UP = 1 << 0;
    const GATEWAY = 1 << 1;
    const HOST = 1 << 2;
    const DYNAMIC = 1 << 3;
    const MODIFIED = 1 << 4;
    const REJECT = 1 << 5;
};

pub const RouteEntry = struct {
    destination: ipv4.IPv4Address,
    netmask: ipv4.IPv4Address,
    gateway: ipv4.IPv4Address,
    interface: []const u8,
    flags: u16,
    metric: u16,
    ref_count: u32,
    use_count: u32,
};

pub const ARPEntry = struct {
    ip_address: ipv4.IPv4Address,
    mac_address: [6]u8,
    timestamp: u64,
    state: enum {
        INCOMPLETE,
        REACHABLE,
        STALE,
        DELAY,
        PROBE,
    },
};

pub const RoutingTable = struct {
    routes: [MAX_ROUTES]RouteEntry,
    route_count: usize,
    arp_cache: [MAX_ARP_ENTRIES]ARPEntry,
    arp_count: usize,
    default_gateway: ipv4.IPv4Address,

    pub fn init() RoutingTable {
        return RoutingTable{
            .routes = undefined,
            .route_count = 0,
            .arp_cache = undefined,
            .arp_count = 0,
            .default_gateway = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } },
        };
    }

    pub fn addRoute(self: *RoutingTable, dest: ipv4.IPv4Address, mask: ipv4.IPv4Address, gateway: ipv4.IPv4Address, iface: []const u8, flags: u16) !void {
        if (self.route_count >= MAX_ROUTES) {
            return error.RoutingTableFull;
        }

        const entry = &self.routes[self.route_count];
        entry.destination = dest;
        entry.netmask = mask;
        entry.gateway = gateway;
        entry.interface = iface;
        entry.flags = flags | RouteFlags.UP;
        entry.metric = 0;
        entry.ref_count = 0;
        entry.use_count = 0;

        self.route_count += 1;
        self.sortRoutes();
    }

    pub fn deleteRoute(self: *RoutingTable, dest: ipv4.IPv4Address, mask: ipv4.IPv4Address) !void {
        var i: usize = 0;
        while (i < self.route_count) : (i += 1) {
            const rt = &self.routes[i];
            if (ipEquals(rt.destination, dest) and ipEquals(rt.netmask, mask)) {
                var j = i;
                while (j < self.route_count - 1) : (j += 1) {
                    self.routes[j] = self.routes[j + 1];
                }
                self.route_count -= 1;
                return;
            }
        }
        return error.RouteNotFound;
    }

    pub fn findRoute(self: *RoutingTable, dest: ipv4.IPv4Address) ?*RouteEntry {
        var best_match: ?*RouteEntry = null;
        var best_prefix_len: u32 = 0;

        var i: usize = 0;
        while (i < self.route_count) : (i += 1) {
            const rt = &self.routes[i];

            if ((rt.flags & RouteFlags.UP) == 0) {
                continue;
            }

            if (isInNetwork(dest, rt.destination, rt.netmask)) {
                const prefix_len = countPrefixBits(rt.netmask);
                if (prefix_len > best_prefix_len) {
                    best_match = rt;
                    best_prefix_len = prefix_len;
                }
            }
        }

        if (best_match) |rt| {
            rt.use_count += 1;
            return rt;
        }

        if (!ipEquals(self.default_gateway, ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } })) {
            return self.findRoute(self.default_gateway);
        }

        return null;
    }

    pub fn setDefaultGateway(self: *RoutingTable, gateway: ipv4.IPv4Address) !void {
        self.default_gateway = gateway;

        const all_zeros = ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } };
        try self.addRoute(all_zeros, all_zeros, gateway, "eth0", RouteFlags.GATEWAY);
    }

    pub fn addARPEntry(self: *RoutingTable, ip: ipv4.IPv4Address, mac: [6]u8) !void {
        var i: usize = 0;
        while (i < self.arp_count) : (i += 1) {
            if (ipEquals(self.arp_cache[i].ip_address, ip)) {
                self.arp_cache[i].mac_address = mac;
                self.arp_cache[i].state = .REACHABLE;
                self.arp_cache[i].timestamp = 0;
                return;
            }
        }

        if (self.arp_count >= MAX_ARP_ENTRIES) {
            self.arp_count = 0;
        }

        const entry = &self.arp_cache[self.arp_count];
        entry.ip_address = ip;
        entry.mac_address = mac;
        entry.state = .REACHABLE;
        entry.timestamp = 0;

        self.arp_count += 1;
    }

    pub fn lookupARP(self: *RoutingTable, ip: ipv4.IPv4Address) ?[6]u8 {
        var i: usize = 0;
        while (i < self.arp_count) : (i += 1) {
            if (ipEquals(self.arp_cache[i].ip_address, ip)) {
                if (self.arp_cache[i].state == .REACHABLE or self.arp_cache[i].state == .STALE) {
                    return self.arp_cache[i].mac_address;
                }
            }
        }
        return null;
    }

    pub fn printRoutes(self: *RoutingTable) void {
        vga.print("Kernel IP routing table\n");
        vga.print("Destination     Gateway         Netmask         Flags Metric Ref Use Iface\n");

        var i: usize = 0;
        while (i < self.route_count) : (i += 1) {
            const rt = &self.routes[i];

            network.printIPv4(rt.destination);
            vga.print(" ");

            if ((rt.flags & RouteFlags.GATEWAY) != 0) {
                network.printIPv4(rt.gateway);
            } else {
                vga.print("*              ");
            }
            vga.print(" ");

            network.printIPv4(rt.netmask);
            vga.print(" ");

            if ((rt.flags & RouteFlags.UP) != 0) vga.put_char('U');
            if ((rt.flags & RouteFlags.GATEWAY) != 0) vga.put_char('G');
            if ((rt.flags & RouteFlags.HOST) != 0) vga.put_char('H');
            if ((rt.flags & RouteFlags.DYNAMIC) != 0) vga.put_char('D');
            vga.print("   ");

            printNumber(rt.metric);
            vga.print("     ");
            printNumber(rt.ref_count);
            vga.print("   ");
            printNumber(rt.use_count);
            vga.print(" ");
            vga.print(rt.interface);
            vga.print("\n");
        }
    }

    pub fn printARPCache(self: *RoutingTable) void {
        vga.print("IP address       HW type     HW address          Flags\n");

        var i: usize = 0;
        while (i < self.arp_count) : (i += 1) {
            const entry = &self.arp_cache[i];

            network.printIPv4(entry.ip_address);
            vga.print("  0x1        ");

            for (entry.mac_address, 0..) |byte, j| {
                printHex(byte);
                if (j < 5) vga.put_char(':');
            }

            vga.print("   ");
            switch (entry.state) {
                .REACHABLE => vga.print("C"),
                .INCOMPLETE => vga.print("I"),
                .STALE => vga.print("S"),
                else => vga.print("?"),
            }
            vga.print("\n");
        }
    }

    fn sortRoutes(self: *RoutingTable) void {
        if (self.route_count <= 1) return;

        var i: usize = 0;
        while (i < self.route_count - 1) : (i += 1) {
            var j: usize = i + 1;
            while (j < self.route_count) : (j += 1) {
                const prefix_i = countPrefixBits(self.routes[i].netmask);
                const prefix_j = countPrefixBits(self.routes[j].netmask);

                if (prefix_j > prefix_i) {
                    const temp = self.routes[i];
                    self.routes[i] = self.routes[j];
                    self.routes[j] = temp;
                }
            }
        }
    }
};

var routing_table: RoutingTable = undefined;

pub fn init() void {
    routing_table = RoutingTable.init();

    const local_ip = network.getLocalIP();
    const netmask = network.getNetmask();
    const gateway = network.getGateway();

    const local_net = ipv4.IPv4Address{
        .octets = .{
            local_ip.octets[0] & netmask.octets[0],
            local_ip.octets[1] & netmask.octets[1],
            local_ip.octets[2] & netmask.octets[2],
            local_ip.octets[3] & netmask.octets[3],
        },
    };

    routing_table.addRoute(local_net, netmask, ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } }, "eth0", 0) catch {};

    routing_table.addRoute(ipv4.IPv4Address{ .octets = .{ 127, 0, 0, 0 } },
                          ipv4.IPv4Address{ .octets = .{ 255, 0, 0, 0 } },
                          ipv4.IPv4Address{ .octets = .{ 0, 0, 0, 0 } },
                          "lo", RouteFlags.HOST) catch {};

    routing_table.setDefaultGateway(gateway) catch {};

    vga.print("Routing table initialized\n");
}

pub fn getRoutingTable() *RoutingTable {
    return &routing_table;
}

pub fn route(dest: ipv4.IPv4Address) ?ipv4.IPv4Address {
    if (routing_table.findRoute(dest)) |entry| {
        if ((entry.flags & RouteFlags.GATEWAY) != 0) {
            return entry.gateway;
        }
        return dest;
    }
    return null;
}

fn ipEquals(a: ipv4.IPv4Address, b: ipv4.IPv4Address) bool {
    return a.octets[0] == b.octets[0] and
           a.octets[1] == b.octets[1] and
           a.octets[2] == b.octets[2] and
           a.octets[3] == b.octets[3];
}

fn isInNetwork(ip: ipv4.IPv4Address, network_addr: ipv4.IPv4Address, netmask: ipv4.IPv4Address) bool {
    return (ip.octets[0] & netmask.octets[0]) == (network_addr.octets[0] & netmask.octets[0]) and
           (ip.octets[1] & netmask.octets[1]) == (network_addr.octets[1] & netmask.octets[1]) and
           (ip.octets[2] & netmask.octets[2]) == (network_addr.octets[2] & netmask.octets[2]) and
           (ip.octets[3] & netmask.octets[3]) == (network_addr.octets[3] & netmask.octets[3]);
}

fn countPrefixBits(mask: ipv4.IPv4Address) u32 {
    var count: u32 = 0;
    for (mask.octets) |byte| {
        var b = byte;
        while (b != 0) : (b <<= 1) {
            if ((b & 0x80) != 0) {
                count += 1;
            } else {
                break;
            }
        }
    }
    return count;
}

fn printNumber(num: u32) void {
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

fn printHex(value: u8) void {
    const hex_chars = "0123456789abcdef";
    vga.put_char(hex_chars[value >> 4]);
    vga.put_char(hex_chars[value & 0x0F]);
}