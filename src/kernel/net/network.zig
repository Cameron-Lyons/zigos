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

pub const OwnedRxPacket = struct {
    data: []const u8,
    mac: [6]u8,
    handle: usize,
    release: *const fn (handle: usize) void,
};

var current_device: ?*const NetworkDevice = null;

const RX_QUEUE_DEPTH = 128;
const TX_QUEUE_DEPTH = 128;
const MAX_PACKET_SIZE = 2048;
const RX_QUEUE_MASK = RX_QUEUE_DEPTH - 1;
const TX_QUEUE_MASK = TX_QUEUE_DEPTH - 1;
const QueueIndex = u8;

comptime {
    if ((RX_QUEUE_DEPTH & RX_QUEUE_MASK) != 0) @compileError("RX_QUEUE_DEPTH must be a power of two");
    if ((TX_QUEUE_DEPTH & TX_QUEUE_MASK) != 0) @compileError("TX_QUEUE_DEPTH must be a power of two");
    if (RX_QUEUE_DEPTH > std.math.maxInt(QueueIndex) + 1) @compileError("RX_QUEUE_DEPTH exceeds QueueIndex capacity");
    if (TX_QUEUE_DEPTH > std.math.maxInt(QueueIndex) + 1) @compileError("TX_QUEUE_DEPTH exceeds QueueIndex capacity");
}

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
    borrowed_ptr: ?[*]const u8 = null,
    borrowed_handle: usize = 0,
    borrowed_release: ?*const fn (handle: usize) void = null,
    data: [MAX_PACKET_SIZE]u8 = [_]u8{0} ** MAX_PACKET_SIZE,
};

const TxEntry = struct {
    len: usize = 0,
    data: [MAX_PACKET_SIZE]u8 = [_]u8{0} ** MAX_PACKET_SIZE,
};

const RxClaim = struct {
    index: QueueIndex,
    entry: *RxEntry,
};

const TxClaim = struct {
    index: QueueIndex,
    entry: *TxEntry,
};

var rx_lock: Spinlock = .{};
var tx_lock: Spinlock = .{};
var rx_pool: [RX_QUEUE_DEPTH]RxEntry = [_]RxEntry{.{}} ** RX_QUEUE_DEPTH;
var tx_pool: [TX_QUEUE_DEPTH]TxEntry = [_]TxEntry{.{}} ** TX_QUEUE_DEPTH;
var rx_queue: [RX_QUEUE_DEPTH]QueueIndex = [_]QueueIndex{0} ** RX_QUEUE_DEPTH;
var tx_queue: [TX_QUEUE_DEPTH]QueueIndex = [_]QueueIndex{0} ** TX_QUEUE_DEPTH;
var rx_free_stack: [RX_QUEUE_DEPTH]QueueIndex = undefined;
var tx_free_stack: [TX_QUEUE_DEPTH]QueueIndex = undefined;
var rx_head: usize = 0;
var rx_tail: usize = 0;
var rx_count: usize = 0;
var rx_free_count: usize = 0;
var tx_head: usize = 0;
var tx_tail: usize = 0;
var tx_count: usize = 0;
var tx_free_count: usize = 0;
var workers_started: bool = false;
var rx_ready: sync.Semaphore = undefined;
var tx_ready: sync.Semaphore = undefined;

pub fn init() void {
    vga.print("Initializing network stack...\n");

    rx_head = 0;
    rx_tail = 0;
    rx_count = 0;
    initFreeStack(&rx_free_stack);
    rx_free_count = rx_free_stack.len;
    tx_head = 0;
    tx_tail = 0;
    tx_count = 0;
    initFreeStack(&tx_free_stack);
    tx_free_count = tx_free_stack.len;
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

    _ = process.create_kernel_process_any_cpu("net-rx-worker", netRxWorker);
    _ = process.create_kernel_process_any_cpu("net-tx-worker", netTxWorker);

    if (smp.isSMPEnabled() and smp.getNumCPUs() > 2) {
        _ = process.create_kernel_process_any_cpu("net-rx-worker-2", netRxWorker);
    }
}

pub fn enqueueRxPacket(packet: []const u8, mac: [6]u8) void {
    if (!workers_started) {
        processPacket(@constCast(packet), mac);
        return;
    }

    const copy_len = @min(packet.len, MAX_PACKET_SIZE);
    rx_lock.acquire();

    if (rx_free_count == 0) {
        rx_lock.release();
        return;
    }

    rx_free_count -= 1;
    const entry_index = rx_free_stack[rx_free_count];
    const entry = &rx_pool[entry_index];
    entry.len = copy_len;
    entry.mac = mac;
    entry.borrowed_ptr = null;
    entry.borrowed_handle = 0;
    entry.borrowed_release = null;
    @memcpy(entry.data[0..copy_len], packet[0..copy_len]);

    rx_queue[rx_head] = entry_index;
    rx_head = (rx_head + 1) & RX_QUEUE_MASK;
    rx_count += 1;
    rx_lock.release();
    rx_ready.signal();
}

pub fn enqueueBorrowedRx(packet: OwnedRxPacket) bool {
    if (!workers_started) {
        processPacket(packet.data, packet.mac);
        packet.release(packet.handle);
        return true;
    }

    rx_lock.acquire();

    if (rx_free_count == 0) {
        rx_lock.release();
        packet.release(packet.handle);
        return false;
    }

    rx_free_count -= 1;
    const entry_index = rx_free_stack[rx_free_count];
    const entry = &rx_pool[entry_index];
    entry.len = packet.data.len;
    entry.mac = packet.mac;
    entry.borrowed_ptr = packet.data.ptr;
    entry.borrowed_handle = packet.handle;
    entry.borrowed_release = packet.release;

    rx_queue[rx_head] = entry_index;
    rx_head = (rx_head + 1) & RX_QUEUE_MASK;
    rx_count += 1;
    rx_lock.release();
    rx_ready.signal();
    return true;
}

pub fn enqueueTxPacket(packet: []const u8) void {
    if (!workers_started) {
        sendPacketNow(packet);
        return;
    }

    const copy_len = @min(packet.len, MAX_PACKET_SIZE);
    tx_lock.acquire();

    if (tx_free_count == 0) {
        tx_lock.release();
        return;
    }

    tx_free_count -= 1;
    const entry_index = tx_free_stack[tx_free_count];
    const entry = &tx_pool[entry_index];
    entry.len = copy_len;
    @memcpy(entry.data[0..copy_len], packet[0..copy_len]);

    tx_queue[tx_head] = entry_index;
    tx_head = (tx_head + 1) & TX_QUEUE_MASK;
    tx_count += 1;
    tx_lock.release();
    tx_ready.signal();
}

fn claimRx() ?RxClaim {
    rx_lock.acquire();
    defer rx_lock.release();

    if (rx_count == 0) return null;

    const entry_index = rx_queue[rx_tail];
    rx_tail = (rx_tail + 1) & RX_QUEUE_MASK;
    rx_count -= 1;
    return .{
        .index = entry_index,
        .entry = &rx_pool[entry_index],
    };
}

fn claimTx() ?TxClaim {
    tx_lock.acquire();
    defer tx_lock.release();

    if (tx_count == 0) return null;

    const entry_index = tx_queue[tx_tail];
    tx_tail = (tx_tail + 1) & TX_QUEUE_MASK;
    tx_count -= 1;
    return .{
        .index = entry_index,
        .entry = &tx_pool[entry_index],
    };
}

fn releaseRx(index: QueueIndex) void {
    rx_lock.acquire();
    rx_pool[index].borrowed_ptr = null;
    rx_pool[index].borrowed_handle = 0;
    rx_pool[index].borrowed_release = null;
    rx_free_stack[rx_free_count] = index;
    rx_free_count += 1;
    rx_lock.release();
}

fn releaseTx(index: QueueIndex) void {
    tx_lock.acquire();
    tx_free_stack[tx_free_count] = index;
    tx_free_count += 1;
    tx_lock.release();
}

fn netRxWorker() void {
    while (true) {
        rx_ready.wait();
        if (claimRx()) |claim| {
            const packet = if (claim.entry.borrowed_ptr) |ptr|
                ptr[0..claim.entry.len]
            else
                claim.entry.data[0..claim.entry.len];
            processPacket(packet, claim.entry.mac);
            if (claim.entry.borrowed_release) |release| {
                release(claim.entry.borrowed_handle);
            }
            releaseRx(claim.index);
        }
    }
}

fn netTxWorker() void {
    while (true) {
        tx_ready.wait();
        if (claimTx()) |claim| {
            sendPacketNow(claim.entry.data[0..claim.entry.len]);
            releaseTx(claim.index);
        }
    }
}

fn initFreeStack(stack: []QueueIndex) void {
    var i: usize = 0;
    while (i < stack.len) : (i += 1) {
        stack[i] = @intCast(stack.len - 1 - i);
    }
}

pub fn getLocalIP() ipv4.IPv4Address {
    return ipv4.getLocalAddress();
}

pub fn getLocalIPRaw() u32 {
    return ipv4.getLocalIP();
}

pub fn getGateway() ipv4.IPv4Address {
    return ipv4.getGatewayAddress();
}

pub fn getGatewayIP() u32 {
    return ipv4.getGatewayIP();
}

pub fn getNetmask() ipv4.IPv4Address {
    return ipv4.getNetmaskAddress();
}

pub fn setLocalIP(ip: ipv4.IPv4Address) void {
    ipv4.setLocalAddress(ip);
}

pub fn setGateway(ip: ipv4.IPv4Address) void {
    ipv4.setGatewayAddress(ip);
}

pub fn setGatewayIP(ip: u32) void {
    ipv4.setGatewayIP(ip);
}

pub fn setNetmask(mask: ipv4.IPv4Address) void {
    ipv4.setNetmaskAddress(mask);
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
    ethernet.setTxSender(device.send);
    ethernet.setMacProvider(device.getMacAddress);
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
