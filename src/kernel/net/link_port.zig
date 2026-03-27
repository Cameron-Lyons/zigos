const std = @import("std");
const sync = @import("../utils/sync.zig");
const ethernet = @import("ethernet.zig");

pub const IngressHandler = *const fn (packet: []const u8, mac: [6]u8) void;

pub const NetworkDevice = struct {
    send: *const fn (data: []const u8) void,
    receive: *const fn () ?[]u8,
    getMacAddress: *const fn () [6]u8,
};

pub const OwnedRxReleaseFn = *const fn (?*anyopaque, handle: usize) void;

pub const OwnedRxPacket = struct {
    data: []const u8,
    mac: [6]u8,
    handle: usize,
    release_context: ?*anyopaque,
    release: OwnedRxReleaseFn,
};

var current_device: ?*const NetworkDevice = null;
var ingress_handler: ?IngressHandler = null;

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
    borrowed_release_context: ?*anyopaque = null,
    borrowed_release: ?OwnedRxReleaseFn = null,
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
    ingress_handler = null;
    rx_ready = sync.Semaphore.init(0);
    tx_ready = sync.Semaphore.init(0);
}

pub fn setIngressHandler(handler: ?IngressHandler) void {
    ingress_handler = handler;
}

pub fn hasIngressHandler() bool {
    return ingress_handler != null;
}

pub fn setNetworkDevice(device: *const NetworkDevice) void {
    current_device = device;
    ethernet.setTxSender(device.send);
    ethernet.setMacProvider(device.getMacAddress);
}

pub fn clearNetworkDevice() void {
    current_device = null;
    ethernet.setTxSender(null);
    ethernet.setMacProvider(null);
}

pub fn hasNetworkDevice() bool {
    return current_device != null;
}

pub fn handleRxPacket(packet: []u8) void {
    enqueueRxPacket(packet, getMacAddress());
}

pub fn startWorkers() void {
    workers_started = false;
}

pub fn enqueueRxPacket(packet: []const u8, mac: [6]u8) void {
    if (!workers_started) {
        if (ingress_handler) |handler| handler(packet, mac);
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
    entry.borrowed_release_context = null;
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
        if (ingress_handler) |handler| handler(packet.data, packet.mac);
        packet.release(packet.release_context, packet.handle);
        return true;
    }

    rx_lock.acquire();

    if (rx_free_count == 0) {
        rx_lock.release();
        packet.release(packet.release_context, packet.handle);
        return false;
    }

    rx_free_count -= 1;
    const entry_index = rx_free_stack[rx_free_count];
    const entry = &rx_pool[entry_index];
    entry.len = packet.data.len;
    entry.mac = packet.mac;
    entry.borrowed_ptr = packet.data.ptr;
    entry.borrowed_handle = packet.handle;
    entry.borrowed_release_context = packet.release_context;
    entry.borrowed_release = packet.release;

    rx_queue[rx_head] = entry_index;
    rx_head = (rx_head + 1) & RX_QUEUE_MASK;
    rx_count += 1;
    rx_lock.release();
    rx_ready.signal();
    return true;
}

pub fn sendPacket(packet: []const u8) void {
    enqueueTxPacket(packet);
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

pub fn sendPacketNow(data: []const u8) void {
    if (current_device) |dev| {
        dev.send(data);
    }
}

pub fn receivePacket() ?[]u8 {
    if (current_device) |dev| {
        return dev.receive();
    }
    return null;
}

pub fn getMacAddress() [6]u8 {
    if (current_device) |dev| {
        return dev.getMacAddress();
    }
    return [_]u8{0} ** 6;
}

pub fn makeRxReleaseAdapter(comptime T: type) OwnedRxReleaseFn {
    return struct {
        fn release(context: ?*anyopaque, handle: usize) void {
            const self: *T = @ptrCast(@alignCast(context orelse return));
            self.releaseReceived(handle);
        }
    }.release;
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
    rx_pool[index].borrowed_release_context = null;
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

            if (ingress_handler) |handler| {
                handler(packet, claim.entry.mac);
            }
            if (claim.entry.borrowed_release) |release| {
                release(claim.entry.borrowed_release_context, claim.entry.borrowed_handle);
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
