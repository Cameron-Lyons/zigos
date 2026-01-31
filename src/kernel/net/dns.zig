const socket = @import("socket.zig");
const ipv4 = @import("ipv4.zig");
const vga = @import("../drivers/vga.zig");


const DNS_PORT = 53;
const DNS_BUFFER_SIZE = 512;
const MAX_DOMAIN_LENGTH = 255;
const MAX_CACHE_ENTRIES = 32;

const DNSHeader = packed struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

const DNSFlags = struct {
    const QR = 1 << 15;
    const OPCODE_MASK = 0x7800;
    const AA = 1 << 10;
    const TC = 1 << 9;
    const RD = 1 << 8;
    const RA = 1 << 7;
    const Z_MASK = 0x70;
    const RCODE_MASK = 0xF;
};

const DNSType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
};

const DNSClass = enum(u16) {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
};

const DNSCacheEntry = struct {
    domain: [MAX_DOMAIN_LENGTH]u8,
    domain_len: usize,
    ip: ipv4.IPv4Address,
    ttl: u32,
    timestamp: u64,
};

pub const DNSClient = struct {
    dns_server: ipv4.IPv4Address,
    cache: [MAX_CACHE_ENTRIES]DNSCacheEntry,
    cache_count: usize,
    next_query_id: u16,

    pub fn init(dns_server: ipv4.IPv4Address) DNSClient {
        return DNSClient{
            .dns_server = dns_server,
            // SAFETY: Initialized by init() before use
            .cache = undefined,
            .cache_count = 0,
            .next_query_id = 1,
        };
    }

    pub fn resolve(self: *DNSClient, domain: []const u8) !ipv4.IPv4Address {
        if (self.lookupCache(domain)) |ip| {
            return ip;
        }

        const sock = try socket.createSocket(.DGRAM, .UDP);
        defer sock.close();

        // SAFETY: filled by the subsequent buildQuery call
        var query_buffer: [DNS_BUFFER_SIZE]u8 = undefined;
        const query_len = self.buildQuery(&query_buffer, domain);

        try sock.sendTo(query_buffer[0..query_len], self.dns_server, DNS_PORT);

        // SAFETY: filled by the subsequent recvFrom call
        var response_buffer: [DNS_BUFFER_SIZE]u8 = undefined;
        // SAFETY: Populated by recvFrom call below
        var src_addr: ipv4.IPv4Address = undefined;
        // SAFETY: Populated by recvFrom call below
        var src_port: u16 = undefined;
        const response_len = try sock.recvFrom(&response_buffer, &src_addr, &src_port);

        const ip = try self.parseResponse(response_buffer[0..response_len], domain);
        self.addToCache(domain, ip, 3600);

        return ip;
    }

    fn buildQuery(self: *DNSClient, buffer: []u8, domain: []const u8) usize {
        var offset: usize = 0;

        const header: *DNSHeader = @ptrCast(@alignCast(&buffer[offset]));
        header.id = @byteSwap(self.next_query_id);
        self.next_query_id +%= 1;
        header.flags = @byteSwap(@as(u16, DNSFlags.RD));
        header.qdcount = @byteSwap(@as(u16, 1));
        header.ancount = 0;
        header.nscount = 0;
        header.arcount = 0;
        offset += @sizeOf(DNSHeader);

        offset += encodeDomainName(buffer[offset..], domain);

        const qtype: *u16 = @ptrCast(@alignCast(&buffer[offset]));
        qtype.* = @byteSwap(@intFromEnum(DNSType.A));
        offset += 2;

        const qclass: *u16 = @ptrCast(@alignCast(&buffer[offset]));
        qclass.* = @byteSwap(@intFromEnum(DNSClass.IN));
        offset += 2;

        return offset;
    }

    fn parseResponse(self: *DNSClient, data: []const u8, domain: []const u8) !ipv4.IPv4Address {
        _ = self;
        _ = domain;

        if (data.len < @sizeOf(DNSHeader)) {
            return error.InvalidResponse;
        }

        const header: *const DNSHeader = @ptrCast(@alignCast(&data[0]));
        const flags = @byteSwap(header.flags);

        if ((flags & DNSFlags.QR) == 0) {
            return error.NotResponse;
        }

        if ((flags & DNSFlags.RCODE_MASK) != 0) {
            return error.DNSError;
        }

        const ancount = @byteSwap(header.ancount);
        if (ancount == 0) {
            return error.NoAnswer;
        }

        var offset: usize = @sizeOf(DNSHeader);

        const qdcount = @byteSwap(header.qdcount);
        var i: u16 = 0;
        while (i < qdcount) : (i += 1) {
            offset = skipDomainName(data, offset);
            offset += 4;
        }

        i = 0;
        while (i < ancount) : (i += 1) {
            offset = skipDomainName(data, offset);

            const rtype: *const u16 = @ptrCast(@alignCast(&data[offset]));
            const rtype_val = @byteSwap(rtype.*);
            offset += 2;

            const rclass: *const u16 = @ptrCast(@alignCast(&data[offset]));
            _ = rclass;
            offset += 2;

            offset += 4;

            const rdlength: *const u16 = @ptrCast(@alignCast(&data[offset]));
            const rdlength_val = @byteSwap(rdlength.*);
            offset += 2;

            if (rtype_val == @intFromEnum(DNSType.A) and rdlength_val == 4) {
                return ipv4.IPv4Address{
                    .octets = .{
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    },
                };
            }

            offset += rdlength_val;
        }

        return error.NoARecord;
    }

    fn encodeDomainName(buffer: []u8, domain: []const u8) usize {
        var offset: usize = 0;
        var label_start: usize = 0;
        var i: usize = 0;

        while (i <= domain.len) : (i += 1) {
            if (i == domain.len or domain[i] == '.') {
                const label_len = i - label_start;
                if (label_len > 0) {
                    buffer[offset] = @intCast(label_len);
                    offset += 1;
                    @memcpy(buffer[offset..offset + label_len], domain[label_start..i]);
                    offset += label_len;
                }
                label_start = i + 1;
            }
        }

        buffer[offset] = 0;
        offset += 1;

        return offset;
    }

    fn skipDomainName(data: []const u8, start: usize) usize {
        var offset = start;

        while (offset < data.len) {
            const len = data[offset];
            if (len == 0) {
                return offset + 1;
            }

            if ((len & 0xC0) == 0xC0) {
                return offset + 2;
            }

            offset += 1 + len;
        }

        return offset;
    }

    fn lookupCache(self: *DNSClient, domain: []const u8) ?ipv4.IPv4Address {
        var i: usize = 0;
        while (i < self.cache_count) : (i += 1) {
            const entry = &self.cache[i];
            if (entry.domain_len == domain.len) {
                var match = true;
                var j: usize = 0;
                while (j < domain.len) : (j += 1) {
                    if (entry.domain[j] != domain[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return entry.ip;
                }
            }
        }
        return null;
    }

    fn addToCache(self: *DNSClient, domain: []const u8, ip: ipv4.IPv4Address, ttl: u32) void {
        if (self.cache_count >= MAX_CACHE_ENTRIES) {
            self.cache_count = 0;
        }

        const entry = &self.cache[self.cache_count];
        const copy_len = @min(domain.len, MAX_DOMAIN_LENGTH - 1);
        @memcpy(entry.domain[0..copy_len], domain[0..copy_len]);
        entry.domain_len = copy_len;
        entry.ip = ip;
        entry.ttl = ttl;
        entry.timestamp = 0;

        self.cache_count += 1;
    }
};

var default_dns_client: ?DNSClient = null;

pub fn init() void {
    const dns_server = ipv4.IPv4Address{ .octets = .{ 8, 8, 8, 8 } };
    default_dns_client = DNSClient.init(dns_server);
    vga.print("DNS client initialized with server 8.8.8.8\n");
}

pub fn resolve(domain: []const u8) !ipv4.IPv4Address {
    if (default_dns_client) |*client| {
        return client.resolve(domain);
    }
    return error.NotInitialized;
}

pub fn setDNSServer(server: ipv4.IPv4Address) void {
    if (default_dns_client) |*client| {
        client.dns_server = server;
    }
}