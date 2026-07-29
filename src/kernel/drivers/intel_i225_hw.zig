// Minimal polled transmit path for the first hardware target's Intel I225-LM.
// The firmware remains responsible for PHY initialization and link negotiation;
// this path attaches only when BAR0, the permanent MAC address, and the queue
// registers are usable. PCI bus mastering stays revoked until VT-d contains the
// requester in its own domain.

const console = @import("../utils/console.zig");
const paging = @import("../memory/paging64.zig");
const intel_vtd = @import("../platform/intel_vtd.zig");
const i225_tx = @import("intel_i225_tx.zig");
const pci = @import("pci.zig");

const PAGE_SIZE: u32 = 4096;
const DMA_FRAME_COUNT: u32 = 2;
const TX_DESCRIPTOR_COUNT: u32 = 64;
const TX_DESCRIPTOR_BYTES: u32 = 16;
const TX_RING_BYTES: u32 = TX_DESCRIPTOR_COUNT * TX_DESCRIPTOR_BYTES;
const BAR_MAP_BYTES: u32 = 0x1_0000;
const BAR_IO_SPACE: u32 = 1 << 0;
const BAR_MEMORY_TYPE_MASK: u32 = 0x6;
const BAR_MEMORY_TYPE_32: u32 = 0;
const BAR_MEMORY_TYPE_64: u32 = 0x4;
const KERNEL_I225_MMIO_VIRTUAL_BASE: usize = 0xFFFF_8000_1000_0000;
const QUEUE_SPIN_LIMIT: u64 = 5_000_000;
const TRANSMIT_SPIN_LIMIT: u64 = 50_000_000;

const REG_STATUS: usize = 0x00008;
const REG_CTRL_EXT: usize = 0x00018;
const REG_IMC: usize = 0x0150C;
const REG_EIMC: usize = 0x01528;
const REG_TCTL: usize = 0x00400;
const REG_RAL0: usize = 0x05400;
const REG_RAH0: usize = 0x05404;
const REG_TDBAL0: usize = 0x0E000;
const REG_TDBAH0: usize = 0x0E004;
const REG_TDLEN0: usize = 0x0E008;
const REG_TDH0: usize = 0x0E010;
const REG_TDT0: usize = 0x0E018;
const REG_TXDCTL0: usize = 0x0E028;

const STATUS_LINK_UP: u32 = 1 << 1;
const CTRL_EXT_DRIVER_LOADED: u32 = 1 << 28;
const TCTL_ENABLE: u32 = 1 << 1;
const TCTL_PAD_SHORT_PACKET: u32 = 1 << 3;
const TCTL_COLLISION_THRESHOLD_MASK: u32 = 0x0000_0FF0;
const TCTL_COLLISION_THRESHOLD: u32 = 15 << 4;
const TCTL_RETRANSMIT_LATE_COLLISION: u32 = 1 << 24;
const TXDCTL_QUEUE_ENABLE: u32 = 1 << 25;
const TXDCTL_THRESHOLDS: u32 = 8 | (1 << 8) | (16 << 16);
const RAH_ADDRESS_VALID: u32 = 1 << 31;

const ADVTXD_TYPE_DATA: u32 = 0x0030_0000;
const ADVTXD_END_OF_PACKET: u32 = 0x0100_0000;
const ADVTXD_INSERT_FCS: u32 = 0x0200_0000;
const ADVTXD_REPORT_STATUS: u32 = 0x0800_0000;
const ADVTXD_EXTENDED: u32 = 0x2000_0000;
const ADVTXD_PAYLOAD_LENGTH_SHIFT: u5 = 14;
const TXD_STATUS_DONE: u32 = 1;

pub const MAX_PAYLOAD_BYTES = i225_tx.MAX_PAYLOAD_BYTES;

const TxDescriptor = extern struct {
    buffer_addr: u64,
    cmd_type_len: u32,
    olinfo_status: u32,
};

comptime {
    if (@sizeOf(TxDescriptor) != TX_DESCRIPTOR_BYTES) @compileError("I225 TX descriptor layout changed");
}

pub const Error = error{
    UnsupportedDevice,
    AlreadyPrepared,
    BarUnmappable,
    BusMasteringNotRevoked,
    DmaAllocationFailed,
    PermanentMacMissing,
    QueueDisableTimeout,
    QueueEnableTimeout,
    DmaIsolationBypassed,
    BusMasterEnableFailed,
};

const Controller = struct {
    bar: usize,
    descriptor_phys: u32,
    buffer_phys: u32,
    mac: [6]u8,
    tail: u32 = 0,

    fn reg32(self: *const Controller, offset: usize) u32 {
        return @as(*volatile u32, @ptrFromInt(self.bar + offset)).*;
    }

    fn writeReg32(self: *const Controller, offset: usize, value: u32) void {
        @as(*volatile u32, @ptrFromInt(self.bar + offset)).* = value;
    }

    fn linkUp(self: *const Controller) bool {
        return (self.reg32(REG_STATUS) & STATUS_LINK_UP) != 0;
    }
};

var prepared = false;
var active = false;
var controller: Controller = undefined;
var active_device: pci.PCIDevice = undefined;
var dma_windows: [DMA_FRAME_COUNT]intel_vtd.DmaWindow = undefined;
var transmitted_frames: u64 = 0;
var failed_frames: u64 = 0;

pub fn prepare(device_info: pci.PCIDevice) Error!void {
    if (prepared) return error.AlreadyPrepared;
    if (!pci.isIntelI225Lm(device_info)) return error.UnsupportedDevice;
    if (pci.busMasteringEnabled(device_info)) return error.BusMasteringNotRevoked;

    const bar_phys = barPhysicalAddress(device_info) orelse return error.BarUnmappable;
    if (bar_phys == 0) return error.BarUnmappable;
    const bar = mapBar(bar_phys);
    var pending = Controller{
        .bar = bar,
        .descriptor_phys = 0,
        .buffer_phys = 0,
        .mac = readPermanentMac(bar) orelse return error.PermanentMacMissing,
    };

    pending.writeReg32(REG_IMC, 0xFFFF_FFFF);
    pending.writeReg32(REG_EIMC, 0xFFFF_FFFF);
    pending.writeReg32(REG_TXDCTL0, 0);
    if (!spinQueueState(&pending, false)) return error.QueueDisableTimeout;

    const frames = paging.alloc_frames(DMA_FRAME_COUNT) orelse return error.DmaAllocationFailed;
    var committed = false;
    errdefer if (!committed) {
        pending.writeReg32(REG_TXDCTL0, 0);
        paging.release_frames(frames, DMA_FRAME_COUNT) catch {};
    };
    zeroFrames(frames, DMA_FRAME_COUNT);
    pending.descriptor_phys = frames;
    pending.buffer_phys = frames + PAGE_SIZE;

    pending.writeReg32(REG_TDLEN0, TX_RING_BYTES);
    pending.writeReg32(REG_TDBAL0, pending.descriptor_phys);
    pending.writeReg32(REG_TDBAH0, 0);
    pending.writeReg32(REG_TDH0, 0);
    pending.writeReg32(REG_TDT0, 0);

    var tctl = pending.reg32(REG_TCTL);
    tctl &= ~TCTL_COLLISION_THRESHOLD_MASK;
    tctl |= TCTL_ENABLE | TCTL_PAD_SHORT_PACKET | TCTL_RETRANSMIT_LATE_COLLISION |
        TCTL_COLLISION_THRESHOLD;
    pending.writeReg32(REG_TCTL, tctl);
    pending.writeReg32(REG_TXDCTL0, TXDCTL_THRESHOLDS | TXDCTL_QUEUE_ENABLE);
    if (!spinQueueState(&pending, true)) return error.QueueEnableTimeout;
    pending.writeReg32(REG_CTRL_EXT, pending.reg32(REG_CTRL_EXT) | CTRL_EXT_DRIVER_LOADED);

    dma_windows = .{
        .{
            .base = pending.descriptor_phys,
            .device_readable = true,
            .device_writable = true,
        },
        .{
            .base = pending.buffer_phys,
            .device_readable = true,
            .device_writable = false,
        },
    };
    controller = pending;
    active_device = device_info;
    transmitted_frames = 0;
    failed_frames = 0;
    prepared = true;
    committed = true;
}

pub fn isolationDomain() ?intel_vtd.DmaDomain {
    if (!prepared) return null;
    return .{ .device = active_device, .windows = &dma_windows };
}

pub fn activate() Error!void {
    if (!prepared or !intel_vtd.requesterProtected(active_device)) {
        return error.DmaIsolationBypassed;
    }
    pci.enableMemoryBusMastering(active_device);
    if (!pci.busMasteringEnabled(active_device)) {
        pci.disableBusMastering(active_device);
        return error.BusMasterEnableFailed;
    }
    active = true;
}

pub fn attached() bool {
    return active;
}

pub fn macAddress() [6]u8 {
    if (!prepared) return [_]u8{0} ** 6;
    return controller.mac;
}

pub fn transmitCount() u64 {
    return transmitted_frames;
}

pub fn failedTransmitCount() u64 {
    return failed_frames;
}

pub fn sendPayload(payload: []const u8) bool {
    if (!active or payload.len == 0 or payload.len > MAX_PAYLOAD_BYTES or !controller.linkUp()) {
        failed_frames +%= 1;
        return false;
    }

    const buffer: [*]u8 = @ptrFromInt(controller.buffer_phys);
    const frame_len = i225_tx.buildEthernetFrame(buffer[0..PAGE_SIZE], controller.mac, payload) catch {
        failed_frames +%= 1;
        return false;
    };

    const descriptor_index = controller.tail;
    const descriptor: *volatile TxDescriptor = @ptrFromInt(
        controller.descriptor_phys + descriptor_index * TX_DESCRIPTOR_BYTES,
    );
    descriptor.* = .{
        .buffer_addr = controller.buffer_phys,
        .cmd_type_len = ADVTXD_TYPE_DATA | ADVTXD_EXTENDED | ADVTXD_INSERT_FCS |
            ADVTXD_END_OF_PACKET | ADVTXD_REPORT_STATUS | @as(u32, @intCast(frame_len)),
        .olinfo_status = @as(u32, @intCast(frame_len)) << ADVTXD_PAYLOAD_LENGTH_SHIFT,
    };
    publishDescriptor();
    controller.tail = (descriptor_index + 1) % TX_DESCRIPTOR_COUNT;
    controller.writeReg32(REG_TDT0, controller.tail);

    var spins: u64 = 0;
    while (spins < TRANSMIT_SPIN_LIMIT) : (spins += 1) {
        if ((descriptor.olinfo_status & TXD_STATUS_DONE) != 0) {
            if (pollDmaFault()) return false;
            transmitted_frames +%= 1;
            return true;
        }
        if ((spins & 0x3FF) == 0 and pollDmaFault()) return false;
        spinHint();
    }
    containFailure("ZIGOS:I225:HW:TX_TIMEOUT_CONTAINED\n");
    return false;
}

fn pollDmaFault() bool {
    if (!intel_vtd.faultMonitoringEnabled()) return false;
    if ((intel_vtd.pollFaultForDevice(active_device) catch {
        containFailure("ZIGOS:I225:HW:FAULT_MONITOR_FAIL_CLOSED\n");
        return true;
    }) != null) {
        containFailure("ZIGOS:I225:HW:DMA_FAULT_CONTAINED\n");
        return true;
    }
    return false;
}

fn containFailure(marker: []const u8) void {
    failed_frames +%= 1;
    active = false;
    pci.disableBusMastering(active_device);
    controller.writeReg32(REG_TXDCTL0, 0);
    console.print(marker);
}

fn barPhysicalAddress(device_info: pci.PCIDevice) ?usize {
    if ((device_info.bar0 & BAR_IO_SPACE) != 0) return null;
    const memory_type = device_info.bar0 & BAR_MEMORY_TYPE_MASK;
    const low = @as(usize, device_info.bar0 & 0xFFFF_FFF0);
    return switch (memory_type) {
        BAR_MEMORY_TYPE_32 => low,
        BAR_MEMORY_TYPE_64 => (@as(usize, device_info.bar1) << 32) | low,
        else => null,
    };
}

fn mapBar(physical: usize) usize {
    var offset: u32 = 0;
    while (offset < BAR_MAP_BYTES) : (offset += PAGE_SIZE) {
        paging.mapKernelBorrowedPage(
            KERNEL_I225_MMIO_VIRTUAL_BASE + offset,
            physical + offset,
            paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE,
        );
    }
    return KERNEL_I225_MMIO_VIRTUAL_BASE;
}

fn readPermanentMac(bar: usize) ?[6]u8 {
    const ral = @as(*volatile u32, @ptrFromInt(bar + REG_RAL0)).*;
    const rah = @as(*volatile u32, @ptrFromInt(bar + REG_RAH0)).*;
    if ((rah & RAH_ADDRESS_VALID) == 0) return null;
    const mac = i225_tx.decodeMac(ral, rah);
    if (!i225_tx.validUnicastMac(mac)) return null;
    return mac;
}

fn spinQueueState(pending: *const Controller, want_enabled: bool) bool {
    var spins: u64 = 0;
    while (spins < QUEUE_SPIN_LIMIT) : (spins += 1) {
        if (((pending.reg32(REG_TXDCTL0) & TXDCTL_QUEUE_ENABLE) != 0) == want_enabled) return true;
        spinHint();
    }
    return false;
}

fn zeroFrames(base: u32, count: u32) void {
    @memset(@as([*]u8, @ptrFromInt(base))[0 .. @as(usize, count) * PAGE_SIZE], 0);
}

fn publishDescriptor() void {
    asm volatile ("mfence" ::: .{ .memory = true });
}

fn spinHint() void {
    asm volatile ("pause");
}

export fn zigosNetworkBootstrapI225Attached() callconv(.c) bool {
    return attached();
}

export fn zigosNetworkBootstrapI225Send(payload_ptr: [*]const u8, payload_len: usize) callconv(.c) bool {
    return sendPayload(payload_ptr[0..payload_len]);
}

export fn zigosNetworkBootstrapI225Mac(output: [*]u8) callconv(.c) bool {
    if (!prepared) return false;
    const mac = macAddress();
    @memcpy(output[0..mac.len], &mac);
    return true;
}
