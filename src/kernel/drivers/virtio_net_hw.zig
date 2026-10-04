const std = @import("std");
const pci = @import("pci.zig");
const transport = @import("virtio_pci.zig");
const virtqueue = @import("virtio_queue.zig");
const ethernet = @import("intel_i225_frame.zig");
const paging = @import("../memory/paging64.zig");
const mmio = @import("../memory/mmio_windows.zig");
const vtd = @import("../platform/intel_vtd.zig");
const clock = @import("../timer/tsc_clock.zig");
const timer = @import("../timer/timer.zig");
const x2apic = @import("../interrupts/x2apic.zig");
const smp = @import("../smp.zig");
const console = @import("../utils/console.zig");

const PAGE: u32 = 4096;
const BUFFER_PAGES = virtqueue.CAPACITY * virtqueue.BUFFER_BYTES / PAGE;
const DMA_PAGES = 2 + BUFFER_PAGES * 2;
const DRIVER_OFFSET = @offsetOf(virtqueue.Ring, "available");
const DEVICE_OFFSET = @offsetOf(virtqueue.Ring, "used");
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;
const READY_STATUS = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
pub const INTERRUPT_VECTOR: u8 = 65; // One selected network device owns this vector.

const Queue = struct {
    state: virtqueue.Queue,
    ring: usize,
    buffers: usize,
    buffer_physical: u32,
    notification: usize,

    fn memory(self: *const Queue) *volatile virtqueue.Ring {
        return @ptrFromInt(self.ring);
    }
    fn buffer(self: *const Queue, id: u16) []u8 {
        return @as([*]u8, @ptrFromInt(self.buffers + @as(usize, id) * virtqueue.BUFFER_BYTES))[0..virtqueue.BUFFER_BYTES];
    }
    fn submit(self: *Queue, id: u16, length: u32) !void {
        try self.state.submit(self.memory(), id, self.buffer_physical + @as(u32, id) * virtqueue.BUFFER_BYTES, length);
    }
    fn notify(self: *const Queue, index: u16) void {
        if (virtqueue.Queue.shouldNotify(self.memory())) reg(u16, self.notification).* = index;
    }
};

const Controller = struct {
    device: pci.PCIDevice,
    common: usize,
    isr: usize,
    msix: usize,
    msix_control: u16,
    mac: [6]u8,
    rx: Queue,
    tx: Queue,
    windows: [4]vtd.DmaWindow,
    submitted_ticks: [virtqueue.CAPACITY]u64 = @as([virtqueue.CAPACITY]u64, @splat(0)),
};

var controller: Controller = undefined;
var prepared: bool = false;
var active: bool = false;
var interrupt_pending: bool = false;
var interrupt_count: u32 = 0;
var empty_interrupts: u8 = 0;

comptime {
    if (@sizeOf(Controller) > 512 or DMA_PAGES * PAGE > 136 * 1024) @compileError("VirtIO network state exceeds its memory budget");
}

pub fn firstDevice() ?pci.PCIDevice {
    return pci.findDevice(transport.VENDOR, transport.NET_DEVICE);
}

pub fn prepare(device: pci.PCIDevice) !void {
    if (prepared) return;
    if (device.vendor_id != transport.VENDOR or device.device_id != transport.NET_DEVICE) return error.UnsupportedDevice;
    if (pci.busMasteringEnabled(device)) return error.BusMasteringNotRevoked;
    const bars = try pci.probeMemoryBars(device);
    var config: [256]u8 = undefined;
    for (0..64) |index| std.mem.writeInt(u32, config[index * 4 ..][0..4], pci.readConfigDword(device.bus, device.device, device.function, @intCast(index * 4)), .little);
    const layout = try transport.parse(&config, &bars);
    pci.enableMemoryDecoding(device);
    const common = try mapRegion(layout.common.physical(&bars), 56, 0);
    reg(u8, common + 20).* = 0;
    const deadline = clock.afterMilliseconds(1000);
    while (reg(u8, common + 20).* != 0) {
        if (deadline.expired()) return error.ResetTimeout;
        std.atomic.spinLoopHint();
    }
    errdefer reg(u8, common + 20).* |= STATUS_FAILED;
    reg(u8, common + 20).* = STATUS_ACKNOWLEDGE | STATUS_DRIVER;
    reg(u32, common).* = 0;
    const low = reg(u32, common + 4).*;
    reg(u32, common).* = 1;
    const high = reg(u32, common + 4).*;
    const features = try transport.negotiate((@as(u64, high) << 32) | low);
    reg(u32, common + 8).* = 0;
    reg(u32, common + 12).* = @truncate(features);
    reg(u32, common + 8).* = 1;
    reg(u32, common + 12).* = @truncate(features >> 32);
    reg(u8, common + 20).* = READY_STATUS;
    if (reg(u8, common + 20).* != READY_STATUS) return error.FeaturesRejected;
    if (reg(u16, common + 18).* < 2) return error.MissingQueue;
    const device_config = try mapRegion(layout.device.physical(&bars), 6, 1);
    var mac: [6]u8 = undefined;
    var coherent = false;
    for (0..8) |_| {
        const generation = reg(u8, common + 21).*;
        for (&mac, 0..) |*byte, index| byte.* = reg(u8, device_config + index).*;
        if (reg(u8, common + 21).* == generation) {
            coherent = true;
            break;
        }
    }
    if (!coherent or !ethernet.validUnicastMac(mac)) return error.InvalidMac;
    const dma = paging.allocIdentityDmaFrames(DMA_PAGES) orelse return error.DmaAllocationFailed;
    errdefer paging.releaseIdentityDmaFrames(dma, DMA_PAGES) catch {};
    const alias = paging.directMapAddress(dma) orelse return error.DmaAllocationFailed;
    @memset(@as([*]u8, @ptrFromInt(alias))[0 .. DMA_PAGES * PAGE], 0);
    var pending = Controller{
        .device = device,
        .common = common,
        .isr = try mapRegion(layout.isr.physical(&bars), 1, 2),
        .msix = try mapRegion(layout.msix_table.physical(&bars), 16, 3),
        .msix_control = @as(u16, layout.msix_capability) + 2,
        .mac = mac,
        .rx = undefined,
        .tx = undefined,
        .windows = .{
            .{ .base = dma, .length = PAGE, .device_readable = true, .device_writable = true },
            .{ .base = dma + PAGE, .length = PAGE, .device_readable = true, .device_writable = true },
            .{ .base = dma + 2 * PAGE, .length = BUFFER_PAGES * PAGE, .device_readable = false, .device_writable = true },
            .{ .base = dma + (2 + BUFFER_PAGES) * PAGE, .length = BUFFER_PAGES * PAGE, .device_readable = true, .device_writable = false },
        },
    };
    pending.rx = try setupQueue(common, 0, dma, alias, dma + 2 * PAGE, alias + 2 * PAGE, layout, &bars, 4);
    pending.tx = try setupQueue(common, 1, dma + PAGE, alias + PAGE, dma + (2 + BUFFER_PAGES) * PAGE, alias + (2 + BUFFER_PAGES) * PAGE, layout, &bars, 5);
    for (0..virtqueue.CAPACITY) |id| try pending.rx.submit(@intCast(id), virtqueue.BUFFER_BYTES);
    controller = pending;
    @atomicStore(bool, &prepared, true, .release);
    console.print("ZIGOS:VIRTIO_NET:PREPARED\n");
}

fn setupQueue(common: usize, index: u16, physical: u32, alias: usize, buffer_physical: u32, buffers: usize, layout: transport.Layout, bars: *const [6]transport.Bar, slot: usize) !Queue {
    reg(u16, common + 22).* = index;
    if (reg(u16, common + 24).* < virtqueue.CAPACITY or reg(u16, common + 28).* != 0) return error.InvalidQueue;
    reg(u16, common + 24).* = virtqueue.CAPACITY;
    if (reg(u16, common + 24).* != virtqueue.CAPACITY) return error.InvalidQueue;
    const notification = try layout.notification(reg(u16, common + 30).*);
    writeAddress(common + 32, physical);
    writeAddress(common + 40, physical + DRIVER_OFFSET);
    writeAddress(common + 48, physical + DEVICE_OFFSET);
    return .{
        .state = .{ .device_writable = index == 0 },
        .ring = alias,
        .buffer_physical = buffer_physical,
        .buffers = buffers,
        .notification = try mapRegion(notification.physical(bars), 2, slot),
    };
}

pub fn isolationDomain() ?vtd.DmaDomain {
    if (!@atomicLoad(bool, &prepared, .acquire)) return null;
    return .{ .device = controller.device, .windows = &controller.windows };
}

pub fn attached() bool {
    return @atomicLoad(bool, &active, .acquire);
}

pub fn activate() !void {
    if (attached()) return;
    if (!prepared or !vtd.requesterProtected(controller.device) or !vtd.faultMonitoringEnabled() or !vtd.interruptIsolationEnabled()) return error.DmaIsolationUnavailable;
    const message = try vtd.routeInterrupt(controller.device, INTERRUPT_VECTOR, smp.irqDestinationId());
    const device = controller.device;
    const control = pci.readConfigWord(device.bus, device.device, device.function, controller.msix_control);
    pci.writeConfigWord(device.bus, device.device, device.function, controller.msix_control, control | 0xC000);
    if (pci.readConfigWord(device.bus, device.device, device.function, controller.msix_control) & 0xC000 != 0xC000) return error.MsixUnavailable;
    reg(u32, controller.msix + 12).* = 1;
    reg(u32, controller.msix).* = @truncate(message.address);
    reg(u32, controller.msix + 4).* = @truncate(message.address >> 32);
    reg(u32, controller.msix + 8).* = message.data;
    if (reg(u32, controller.msix).* != @as(u32, @truncate(message.address)) or
        reg(u32, controller.msix + 4).* != @as(u32, @truncate(message.address >> 32)) or
        reg(u32, controller.msix + 8).* != message.data or
        reg(u32, controller.msix + 12).* & 1 == 0) return error.MsixUnavailable;
    reg(u16, controller.common + 16).* = 0xFFFF; // No config-change interrupts.
    errdefer contain("Activation");
    for (0..2) |index| {
        reg(u16, controller.common + 22).* = @intCast(index);
        reg(u16, controller.common + 26).* = 0;
        if (reg(u16, controller.common + 26).* != 0) return error.MsixUnavailable;
        reg(u16, controller.common + 28).* = 1;
        if (reg(u16, controller.common + 28).* != 1) return error.QueueEnableFailed;
    }
    pci.enableMemoryBusMastering(device);
    if (!pci.busMasteringEnabled(device)) return error.BusMasterEnableFailed;
    @atomicStore(bool, &active, true, .release);
    reg(u8, controller.common + 20).* = READY_STATUS | STATUS_DRIVER_OK;
    if (reg(u8, controller.common + 20).* != READY_STATUS | STATUS_DRIVER_OK) return error.DeviceNotReady;
    pci.writeConfigWord(device.bus, device.device, device.function, controller.msix_control, (control | 0x8000) & ~@as(u16, 0x4000));
    reg(u32, controller.msix + 12).* = 0;
    if (pci.readConfigWord(device.bus, device.device, device.function, controller.msix_control) & 0xC000 != 0x8000 or
        reg(u32, controller.msix + 12).* & 1 != 0) return error.MsixUnavailable;
    controller.rx.notify(0);
    console.print("ZIGOS:VIRTIO_NET:DMA_AND_MSIX_READY\n");
}

pub fn handleInterrupt() void {
    if (attached()) {
        reg(u32, controller.msix + 12).* = 1;
        _ = @atomicRmw(u32, &interrupt_count, .Add, 1, .monotonic);
        @atomicStore(bool, &interrupt_pending, true, .release);
    }
    x2apic.acknowledge();
}

fn contain(reason: []const u8) void {
    @atomicStore(bool, &active, false, .release);
    reg(u32, controller.msix + 12).* = 1;
    pci.disableBusMastering(controller.device);
    reg(u8, controller.common + 20).* |= STATUS_FAILED;
    // DMA allocations remain pinned after publication to VT-d.
    console.print("ZIGOS:VIRTIO_NET:FAILURE_CONTAINED ");
    console.print(reason);
    console.print("\n");
}

fn service() bool {
    timer.synchronize();
    return serviceAt(HardwareService, timer.getTicks());
}

const HardwareService = struct {
    fn fault() !bool {
        return (try vtd.pollFaultForDevice(controller.device)) != null;
    }

    fn statusReady() bool {
        return reg(u8, controller.common + 20).* == READY_STATUS | STATUS_DRIVER_OK;
    }

    fn containFailure(reason: []const u8) void {
        contain(reason);
    }
};

fn serviceAt(comptime Backend: type, now: u64) bool {
    if (!attached()) return false;
    const fault = Backend.fault() catch |err| {
        Backend.containFailure(@errorName(err));
        return false;
    };
    if (fault or !Backend.statusReady()) {
        Backend.containFailure(if (fault) "DMAFault" else "DeviceStatus");
        return false;
    }
    var progress = false;
    for (0..virtqueue.CAPACITY) |_| {
        const completion = controller.tx.state.complete(controller.tx.memory()) catch |err| {
            Backend.containFailure(@errorName(err));
            return false;
        };
        if (completion == null) break;
        progress = true;
    }
    if (nextWake()) |deadline| {
        if (now >= deadline) {
            Backend.containFailure("TransmitTimeout");
            return false;
        }
    }
    const rx_ready = controller.rx.state.completionReady(controller.rx.memory());
    // A polled completion can precede its MSI-X. Count only interrupts without
    // intervening queue progress, including progress observed before delivery.
    if (progress or rx_ready) empty_interrupts = 0;
    if (@atomicRmw(bool, &interrupt_pending, .Xchg, false, .acq_rel)) {
        if (!progress and !rx_ready) empty_interrupts +|= 1;
        if (empty_interrupts >= 8) {
            Backend.containFailure("EmptyInterruptStorm");
            return false;
        }
    }
    return true;
}

fn rearm() void {
    if (!attached()) return;
    reg(u32, controller.msix + 12).* = 0;
    virtqueue.publish();
    if (controller.rx.state.completionReady(controller.rx.memory()) or controller.tx.state.completionReady(controller.tx.memory())) {
        @atomicStore(bool, &interrupt_pending, true, .release);
        @import("../event_wake.zig").raise(.network);
    }
}

pub fn sendPayload(destination: [6]u8, payload: []const u8) bool {
    if (!service()) return false;
    defer rearm();
    const id = controller.tx.state.freeId() orelse return false;
    const buffer = controller.tx.buffer(id);
    @memset(buffer[0..virtqueue.HEADER_BYTES], 0);
    const length = ethernet.buildEthernetFrame(buffer[virtqueue.HEADER_BYTES..], destination, controller.mac, payload) catch return false;
    controller.tx.submit(id, @intCast(length + virtqueue.HEADER_BYTES)) catch return false;
    controller.submitted_ticks[id] = timer.getTicks();
    controller.tx.notify(1);
    return true;
}

pub const ReceiveResult = @import("intel_i225_hw.zig").ReceiveResult;

pub fn pollReceive(output: []u8) ReceiveResult {
    if (!service()) return .{ .status = .failed };
    defer rearm();
    const completion = (controller.rx.state.complete(controller.rx.memory()) catch |err| {
        contain(@errorName(err));
        return .{ .status = .failed };
    }) orelse return .{ .status = .empty };
    defer {
        controller.rx.submit(completion.id, virtqueue.BUFFER_BYTES) catch |err| contain(@errorName(err));
        if (attached()) controller.rx.notify(0);
    }
    const frame = virtqueue.receivedFrame(controller.rx.buffer(completion.id)[0..completion.length]) catch return .{ .status = .dropped };
    const view = ethernet.parseEthernetFrame(frame, controller.mac) catch return .{ .status = .dropped };
    if (view.payload.len > output.len) return .{ .status = .dropped };
    @memcpy(output[0..view.payload.len], view.payload);
    return .{ .status = .frame, .length = view.payload.len };
}

pub fn workPending() bool {
    return workPendingAt(timer.getTicks());
}

fn workPendingAt(now_ticks: u64) bool {
    if (!attached()) return false;
    if (@atomicLoad(bool, &interrupt_pending, .acquire) or
        controller.rx.state.completionReady(controller.rx.memory()) or
        controller.tx.state.completionReady(controller.tx.memory())) return true;
    const deadline = nextWake() orelse return false;
    return now_ticks >= deadline;
}

pub fn nextWake() ?u64 {
    if (!attached()) return null;
    return controller.tx.state.nextTransmitWake(&controller.submitted_ticks, timer.TICKS_PER_SECOND);
}

pub fn interruptCount() u32 {
    return @atomicLoad(u32, &interrupt_count, .monotonic);
}

pub fn macAddress() [6]u8 {
    return if (prepared) controller.mac else @as([6]u8, @splat(0));
}

fn reg(comptime T: type, address: usize) *volatile T {
    return @ptrFromInt(address);
}

fn writeAddress(address: usize, value: u64) void {
    reg(u32, address).* = @truncate(value);
    reg(u32, address + 4).* = @truncate(value >> 32);
}

test "VirtIO idle transmit watchdog drains completions and contains stalls or malformed ownership once" {
    const Backend = struct {
        var contained: usize = 0;
        var reason: []const u8 = "";

        fn fault() !bool {
            return false;
        }

        fn statusReady() bool {
            return true;
        }

        fn containFailure(value: []const u8) void {
            contained += 1;
            reason = value;
            @atomicStore(bool, &active, false, .release);
        }
    };
    const saved_prepared = prepared;
    const saved_active = attached();
    const saved_controller: ?Controller = if (prepared) controller else null;
    const saved_pending = @atomicLoad(bool, &interrupt_pending, .acquire);
    const saved_empty = empty_interrupts;
    defer {
        if (saved_controller) |previous| controller = previous;
        prepared = saved_prepared;
        @atomicStore(bool, &active, saved_active, .release);
        @atomicStore(bool, &interrupt_pending, saved_pending, .release);
        empty_interrupts = saved_empty;
    }
    var tx_ring = std.mem.zeroes(virtqueue.Ring);
    var rx_ring = std.mem.zeroes(virtqueue.Ring);
    controller = .{
        .device = std.mem.zeroes(pci.PCIDevice),
        .common = 0,
        .isr = 0,
        .msix = 0,
        .msix_control = 0,
        .mac = @splat(0),
        .rx = .{ .state = .{ .device_writable = true }, .ring = @intFromPtr(&rx_ring), .buffers = 0, .buffer_physical = 0, .notification = 0 },
        .tx = .{ .state = .{ .device_writable = false }, .ring = @intFromPtr(&tx_ring), .buffers = 0, .buffer_physical = 0x1000, .notification = 0 },
        .windows = std.mem.zeroes([4]vtd.DmaWindow),
    };
    prepared = true;
    @atomicStore(bool, &active, true, .release);
    @atomicStore(bool, &interrupt_pending, false, .release);
    empty_interrupts = 7;
    Backend.contained = 0;
    Backend.reason = "";
    try std.testing.expect(nextWake() == null);
    try controller.tx.submit(0, 128);
    controller.submitted_ticks[0] = 107;
    try controller.tx.submit(31, 128);
    controller.submitted_ticks[31] = 108;
    try std.testing.expectEqual(@as(?u64, 207), nextWake());
    try std.testing.expect(!workPendingAt(206));
    // Out-of-order completions are drained before checking an expired deadline.
    tx_ring.used.entries[0] = .{ .id = 31, .length = 0 };
    tx_ring.used.index = 1;
    try std.testing.expect(workPendingAt(150));
    try std.testing.expect(serviceAt(Backend, 150));
    try std.testing.expectEqual(@as(?u64, 207), nextWake());
    try std.testing.expectEqual(@as(u8, 0), empty_interrupts);
    tx_ring.used.entries[1] = .{ .id = 0, .length = 0 };
    tx_ring.used.index = 2;
    try std.testing.expect(serviceAt(Backend, 207));
    try std.testing.expect(nextWake() == null);
    try std.testing.expect(!workPendingAt(207));
    @atomicStore(bool, &interrupt_pending, true, .release);
    try std.testing.expect(serviceAt(Backend, 208));
    try std.testing.expectEqual(@as(u8, 1), empty_interrupts);
    try std.testing.expectEqual(@as(usize, 0), Backend.contained);

    try controller.tx.submit(0, 128);
    controller.submitted_ticks[0] = 300;
    try std.testing.expectEqual(@as(?u64, 400), nextWake());
    try std.testing.expect(!workPendingAt(399));
    try std.testing.expect(workPendingAt(400));
    try std.testing.expect(!serviceAt(Backend, 400));
    try std.testing.expectEqual(@as(usize, 1), Backend.contained);
    try std.testing.expectEqualStrings("TransmitTimeout", Backend.reason);
    try std.testing.expectEqual(@as(u32, 1), controller.tx.state.occupied);
    try std.testing.expect(nextWake() == null);
    try std.testing.expect(!workPendingAt(400));
    try std.testing.expect(!serviceAt(Backend, 401));
    try std.testing.expectEqual(@as(usize, 1), Backend.contained);

    // A malformed completion at the deadline is an ownership failure, and
    // containment must preserve its DMA buffers rather than reclaiming them.
    controller.tx.state = .{ .device_writable = false };
    tx_ring = std.mem.zeroes(virtqueue.Ring);
    @atomicStore(bool, &active, true, .release);
    try controller.tx.submit(0, 128);
    controller.submitted_ticks[0] = 500;
    tx_ring.used.entries[0] = .{ .id = virtqueue.CAPACITY, .length = 0 };
    tx_ring.used.index = 1;
    try std.testing.expect(workPendingAt(600));
    try std.testing.expect(!serviceAt(Backend, 600));
    try std.testing.expectEqualStrings("InvalidCompletion", Backend.reason);
    try std.testing.expectEqual(@as(usize, 2), Backend.contained);
    try std.testing.expectEqual(@as(u32, 1), controller.tx.state.occupied);
    try std.testing.expectEqual(@as(u16, 0), controller.tx.state.used_index);
    try std.testing.expect(nextWake() == null);
    try std.testing.expect(!workPendingAt(600));
    try std.testing.expect(!serviceAt(Backend, 601));
    try std.testing.expectEqual(@as(usize, 2), Backend.contained);
}

fn mapRegion(physical: u64, length: usize, slot: usize) !usize {
    const address = std.math.cast(usize, physical) orelse return error.InvalidRegion;
    const offset = address % PAGE;
    if (slot >= 6 or length == 0 or length > PAGE * 2 - offset) return error.InvalidRegion;
    const virtual = mmio.virtio_net.base + slot * PAGE * 2;
    var page: usize = 0;
    while (page < offset + length) : (page += PAGE) paging.mapKernelBorrowedPage(virtual + page, address - offset + page, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE);
    return virtual + offset;
}
