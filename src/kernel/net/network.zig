const std = @import("std");
const vga = @import("../drivers/vga.zig");
const rtl8139 = @import("../drivers/rtl8139.zig");
const process = @import("../process/process.zig");
const smp = @import("../smp/smp.zig");
const sync = @import("../utils/sync.zig");
const ethernet = @import("ethernet.zig");
const arp = @import("arp.zig");
pub const ipv4 = @import("ipv4.zig");
const icmp = @import("icmp.zig");
const tcp = @import("tcp.zig");
const udp = @import("udp.zig");

pub const NetworkDevice = struct {
    send: *const fn (data: []const u8) void,
    receive: *const fn () ?[]u8,
    getMacAddress: *const fn () [6]u8,
};

var current_device: ?*const NetworkDevice = null;

const RX_QUEUE_DEPTH = 128;
const TX_QUEUE_DEPTH = 128;
const MAX_PACKET_SIZE = 2048;

const Spinlock = struct {
    locked: u32 = 0,

    fn acquire(self: *Spinlock) void {
        while (@cmpxchgWeak(u32, &self.locked, 0, 1, .acquire, .monotonic) != null) {
            while (@atomicLoad(u32, &self.locked, .monotonic) != 0) {
                asm volatile ("pause");
            }
        }
    }

    fn release(self: *Spinlock) void {
        @atomicStore(u32, &self.locked, 0, .release);
    }
};

const RxEntry = struct {
    len: usize = 0,
    mac: [6]u8 = [_]u8{0} ** 6,
    data: [MAX_PACKET_SIZE]u8 = [_]u8{0} ** MAX_PACKET_SIZE,
};

const TxEntry = struct {
    len: usize = 0,
    data: [MAX_PACKET_SIZE]u8 = [_]u8{0} ** MAX_PACKET_SIZE,
};

var rx_lock: Spinlock = .{};
var tx_lock: Spinlock = .{};
var rx_queue: [RX_QUEUE_DEPTH]RxEntry = [_]RxEntry{.{}} ** RX_QUEUE_DEPTH;
var tx_queue: [TX_QUEUE_DEPTH]TxEntry = [_]TxEntry{.{}} ** TX_QUEUE_DEPTH;
var rx_head: usize = 0;
var rx_tail: usize = 0;
var rx_count: usize = 0;
var tx_head: usize = 0;
var tx_tail: usize = 0;
var tx_count: usize = 0;
var workers_started: bool = false;
var rx_ready: sync.Semaphore = undefined;
var tx_ready: sync.Semaphore = undefined;

pub fn init() void {
    vga.print("Initializing network stack...\n");

    rx_head = 0;
    rx_tail = 0;
    rx_count = 0;
    tx_head = 0;
    tx_tail = 0;
    tx_count = 0;
    workers_started = false;
    rx_ready = sync.Semaphore.init(0);
    tx_ready = sync.Semaphore.init(0);

    ethernet.init();
    arp.init();
    ipv4.init();
    icmp.init();
    tcp.init();
    udp.init();

    vga.print("Network stack initialized!\n");
}

pub fn handleRxPacket(packet: []u8) void {
    enqueueRxPacket(packet, getMacAddress());
}

pub fn startWorkers() void {
    if (workers_started) return;
    workers_started = true;

    _ = process.create_kernel_process("net-rx-worker", netRxWorker);
    _ = process.create_kernel_process("net-tx-worker", netTxWorker);

    if (smp.isSMPEnabled() and smp.getNumCPUs() > 2) {
        _ = process.create_kernel_process("net-rx-worker-2", netRxWorker);
    }
}

pub fn enqueueRxPacket(packet: []const u8, mac: [6]u8) void {
    if (!workers_started) {
        processPacket(@constCast(packet), mac);
        return;
    }

    const copy_len = @min(packet.len, MAX_PACKET_SIZE);
    rx_lock.acquire();

    if (rx_count >= RX_QUEUE_DEPTH) {
        rx_lock.release();
        return;
    }

    rx_queue[rx_head].len = copy_len;
    rx_queue[rx_head].mac = mac;
    @memcpy(rx_queue[rx_head].data[0..copy_len], packet[0..copy_len]);

    rx_head = (rx_head + 1) % RX_QUEUE_DEPTH;
    rx_count += 1;
    rx_lock.release();
    rx_ready.signal();
}

pub fn enqueueTxPacket(packet: []const u8) void {
    if (!workers_started) {
        sendPacketNow(packet);
        return;
    }

    const copy_len = @min(packet.len, MAX_PACKET_SIZE);
    tx_lock.acquire();

    if (tx_count >= TX_QUEUE_DEPTH) {
        tx_lock.release();
        return;
    }

    tx_queue[tx_head].len = copy_len;
    @memcpy(tx_queue[tx_head].data[0..copy_len], packet[0..copy_len]);

    tx_head = (tx_head + 1) % TX_QUEUE_DEPTH;
    tx_count += 1;
    tx_lock.release();
    tx_ready.signal();
}

fn popRx() ?RxEntry {
    rx_lock.acquire();
    defer rx_lock.release();

    if (rx_count == 0) return null;

    const entry = rx_queue[rx_tail];
    rx_tail = (rx_tail + 1) % RX_QUEUE_DEPTH;
    rx_count -= 1;
    return entry;
}

fn popTx() ?TxEntry {
    tx_lock.acquire();
    defer tx_lock.release();

    if (tx_count == 0) return null;

    const entry = tx_queue[tx_tail];
    tx_tail = (tx_tail + 1) % TX_QUEUE_DEPTH;
    tx_count -= 1;
    return entry;
}

fn netRxWorker() void {
    while (true) {
        rx_ready.wait();
        if (popRx()) |entry| {
            processPacket(entry.data[0..entry.len], entry.mac);
        }
    }
}

fn netTxWorker() void {
    while (true) {
        tx_ready.wait();
        if (popTx()) |entry| {
            sendPacketNow(entry.data[0..entry.len]);
        }
    }
}

var local_ip: u32 = 0x0A000002;
var gateway_ip: u32 = 0x0A000001;
var netmask: u32 = 0xFFFFFF00;

pub fn getLocalIP() ipv4.IPv4Address {
    return ipv4.IPv4Address{
        .octets = .{
            @intCast((local_ip >> 24) & 0xFF),
            @intCast((local_ip >> 16) & 0xFF),
            @intCast((local_ip >> 8) & 0xFF),
            @intCast(local_ip & 0xFF),
        },
    };
}

pub fn getLocalIPRaw() u32 {
    return local_ip;
}

pub fn getGateway() ipv4.IPv4Address {
    return ipv4.IPv4Address{
        .octets = .{
            @intCast((gateway_ip >> 24) & 0xFF),
            @intCast((gateway_ip >> 16) & 0xFF),
            @intCast((gateway_ip >> 8) & 0xFF),
            @intCast(gateway_ip & 0xFF),
        },
    };
}

pub fn getGatewayIP() u32 {
    return gateway_ip;
}

pub fn getNetmask() ipv4.IPv4Address {
    return ipv4.IPv4Address{
        .octets = .{
            @intCast((netmask >> 24) & 0xFF),
            @intCast((netmask >> 16) & 0xFF),
            @intCast((netmask >> 8) & 0xFF),
            @intCast(netmask & 0xFF),
        },
    };
}

pub fn setLocalIP(ip: ipv4.IPv4Address) void {
    local_ip = (@as(u32, ip.octets[0]) << 24) |
        (@as(u32, ip.octets[1]) << 16) |
        (@as(u32, ip.octets[2]) << 8) |
        ip.octets[3];
}

pub fn setGateway(ip: ipv4.IPv4Address) void {
    gateway_ip = (@as(u32, ip.octets[0]) << 24) |
        (@as(u32, ip.octets[1]) << 16) |
        (@as(u32, ip.octets[2]) << 8) |
        ip.octets[3];
}

pub fn setGatewayIP(ip: u32) void {
    gateway_ip = ip;
}

pub fn setNetmask(mask: ipv4.IPv4Address) void {
    netmask = (@as(u32, mask.octets[0]) << 24) |
        (@as(u32, mask.octets[1]) << 16) |
        (@as(u32, mask.octets[2]) << 8) |
        mask.octets[3];
}

pub fn printIPv4(ip: ipv4.IPv4Address) void {
    printNumber(ip.octets[0]);
    vga.put_char('.');
    printNumber(ip.octets[1]);
    vga.put_char('.');
    printNumber(ip.octets[2]);
    vga.put_char('.');
    printNumber(ip.octets[3]);
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

pub fn parseIPv4(str: []const u8) ?u32 {
    var ip: u32 = 0;
    var octet: u32 = 0;
    var octet_count: u8 = 0;

    for (str) |c| {
        if (c == '.') {
            if (octet > 255 or octet_count >= 3) {
                return null;
            }
            ip = (ip << 8) | octet;
            octet = 0;
            octet_count += 1;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            if (octet > 255) {
                return null;
            }
        } else {
            return null;
        }
    }

    if (octet_count != 3 or octet > 255) {
        return null;
    }

    return (ip << 8) | octet;
}

pub fn formatIPv4(ip: u32, buf: []u8) []u8 {
    const a = (ip >> 24) & 0xFF;
    const b = (ip >> 16) & 0xFF;
    const c = (ip >> 8) & 0xFF;
    const d = ip & 0xFF;

    const len = std.fmt.formatIntBuf(buf[0..], a, 10, .lower, .{});
    buf[len] = '.';
    const len2 = std.fmt.formatIntBuf(buf[len + 1 ..], b, 10, .lower, .{});
    buf[len + 1 + len2] = '.';
    const len3 = std.fmt.formatIntBuf(buf[len + 1 + len2 + 1 ..], c, 10, .lower, .{});
    buf[len + 1 + len2 + 1 + len3] = '.';
    const len4 = std.fmt.formatIntBuf(buf[len + 1 + len2 + 1 + len3 + 1 ..], d, 10, .lower, .{});

    return buf[0 .. len + 1 + len2 + 1 + len3 + 1 + len4];
}

pub fn ping(dst_ip: u32) void {
    const data = "Hello from ZigOS!";
    icmp.sendEchoRequest(dst_ip, 1, 1, data) catch |err| {
        vga.print("Ping failed: ");
        vga.print(@errorName(err));
        vga.print("\n");
    };
}

pub fn setNetworkDevice(device: *const NetworkDevice) void {
    current_device = device;
}

pub fn sendPacket(data: []const u8) void {
    enqueueTxPacket(data);
}

pub fn sendPacketNow(data: []const u8) void {
    if (current_device) |dev| {
        dev.send(data);
    } else if (rtl8139.isInitialized()) {
        rtl8139.send(data);
    }
}

pub fn receivePacket() ?[]u8 {
    if (current_device) |dev| {
        return dev.receive();
    } else if (rtl8139.isInitialized()) {
        return rtl8139.receive();
    }
    return null;
}

pub fn getMacAddress() [6]u8 {
    if (current_device) |dev| {
        return dev.getMacAddress();
    } else if (rtl8139.isInitialized()) {
        return rtl8139.getMacAddress();
    }
    return [_]u8{0} ** 6;
}

pub fn processPacket(packet: []const u8, mac: [6]u8) void {
    _ = mac;
    ethernet.handleRxPacket(@constCast(packet));
}
