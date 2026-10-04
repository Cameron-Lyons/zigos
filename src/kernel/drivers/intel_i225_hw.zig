const std = @import("std");
const console = @import("../utils/console.zig");
const spin = @import("../utils/spin.zig");
const mmio_windows = @import("../memory/mmio_windows.zig");
const paging = @import("../memory/paging64.zig");
const intel_vtd = @import("../platform/intel_vtd.zig");
const timer = @import("../timer/timer.zig");
const tsc_clock = @import("../timer/tsc_clock.zig");
const x2apic = @import("../interrupts/x2apic.zig");
const i225_frame = @import("intel_i225_frame.zig");
const i225_irq = @import("intel_i225_irq.zig");
const i225_rx = @import("intel_i225_rx.zig");
const i225_tx = @import("intel_i225_tx.zig");
const pci = @import("pci.zig");
const smp = @import("../smp.zig");

pub const INTERRUPT_STATE_USES_PROTOCOL_ORDERING = true;

const PAGE_SIZE: u32 = 4096;
const TX_DESCRIPTOR_FRAME: u32 = 0;
const TX_BUFFER_FIRST_FRAME: u32 = 1;
const TX_BUFFER_FRAME_COUNT: u32 = i225_tx.BUFFER_REGION_BYTES / PAGE_SIZE;
const RX_DESCRIPTOR_FRAME: u32 = TX_BUFFER_FIRST_FRAME + TX_BUFFER_FRAME_COUNT;
const RX_BUFFER_FIRST_FRAME: u32 = RX_DESCRIPTOR_FRAME + 1;
const RX_BUFFER_FRAME_COUNT: u32 = i225_rx.BUFFER_REGION_BYTES / PAGE_SIZE;
const DMA_FRAME_COUNT: u32 = RX_BUFFER_FIRST_FRAME + RX_BUFFER_FRAME_COUNT;
const DMA_WINDOW_COUNT: usize = 4;
const BAR_MAP_BYTES: u32 = 0x1_0000;
const QUEUE_STATE_TIMEOUT_MILLISECONDS: u64 = 1000;
const TRANSMIT_TIMEOUT_TICKS: u64 = timer.TICKS_PER_SECOND;

const REG_STATUS: usize = 0x00008;
const REG_CTRL_EXT: usize = 0x00018;
const REG_RCTL: usize = 0x00100;
const REG_TCTL: usize = 0x00400;
const REG_SRRCTL0: usize = 0x0C00C;
const REG_RDBAL0: usize = 0x0C000;
const REG_RDBAH0: usize = 0x0C004;
const REG_RDLEN0: usize = 0x0C008;
const REG_RDH0: usize = 0x0C010;
const REG_RDT0: usize = 0x0C018;
const REG_RXDCTL0: usize = 0x0C028;
const REG_ICR: usize = 0x01500;
const REG_IMS: usize = 0x01508;
const REG_IMC: usize = 0x0150C;
const REG_EIMC: usize = 0x01528;
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
const RCTL_ENABLE: u32 = 1 << 1;
const RCTL_STORE_BAD_PACKET: u32 = 1 << 2;
const RCTL_UNICAST_PROMISCUOUS: u32 = 1 << 3;
const RCTL_MULTICAST_PROMISCUOUS: u32 = 1 << 4;
const RCTL_LONG_PACKET_ENABLE: u32 = 1 << 5;
const RCTL_LOOPBACK_MASK: u32 = 0xC0;
const RCTL_BROADCAST_ACCEPT: u32 = 1 << 15;
const RCTL_SIZE_256: u32 = 0x0003_0000;
const RCTL_STRIP_CRC: u32 = 1 << 26;
const TXDCTL_QUEUE_ENABLE: u32 = 1 << 25;
const TXDCTL_THRESHOLDS: u32 = 8 | (1 << 8) | (16 << 16);
const RXDCTL_QUEUE_ENABLE: u32 = 1 << 25;
const RXDCTL_THRESHOLDS: u32 = 8 | (8 << 8) | (4 << 16);
const SRRCTL_PACKET_BUFFER_MASK: u32 = 0x7F;
const SRRCTL_HEADER_BUFFER_MASK: u32 = 0x3F << 8;
const SRRCTL_DESCRIPTOR_TYPE_MASK: u32 = 0x7 << 25;
const SRRCTL_PACKET_BUFFER_2048: u32 = 2;
const SRRCTL_HEADER_BUFFER_256: u32 = 4 << 8;
const SRRCTL_ADVANCED_ONE_BUFFER: u32 = 1 << 25;
const RAH_ADDRESS_VALID: u32 = 1 << 31;
const PENDING_INTERRUPT_EVENT: u32 = 1 << 30;

comptime {
    if (@as(usize, BAR_MAP_BYTES) > mmio_windows.intel_i225.bytes) {
        @compileError("I225 BAR mapping exceeds its reserved MMIO window");
    }
    if (i225_irq.MAX_TX_COMPLETIONS_PER_SERVICE != i225_tx.CAPACITY) {
        @compileError("I225 interrupt TX service bound diverged from ring capacity");
    }
    if (i225_irq.MAX_RX_FRAMES_PER_SERVICE != 1) {
        @compileError("I225 receive service must remain one frame per pass");
    }
}

pub const MAX_PAYLOAD_BYTES = i225_frame.MAX_PAYLOAD_BYTES;
pub const INTERRUPT_VECTOR = i225_irq.INTERRUPT_VECTOR;

pub const ReceiveStatus = enum(u8) {
    empty = 0,
    frame = 1,
    dropped = 2,
    failed = 3,
};

pub const ReceiveResult = struct {
    status: ReceiveStatus,
    length: usize = 0,
};

const DmaAddress = struct {
    physical: u32 = 0,
    alias: usize = 0,

    fn offset(self: DmaAddress, byte_offset: u32) DmaAddress {
        return .{
            .physical = self.physical + byte_offset,
            .alias = self.alias + @as(usize, byte_offset),
        };
    }

    fn frame(self: DmaAddress, frame_index: u32) DmaAddress {
        return self.offset(frame_index * PAGE_SIZE);
    }
};

pub const Error = error{
    UnsupportedDevice,
    AlreadyPrepared,
    BarUnmappable,
    BusMasteringNotRevoked,
    DmaAllocationFailed,
    PermanentMacMissing,
    TxQueueDisableTimeout,
    TxQueueEnableTimeout,
    RxQueueDisableTimeout,
    RxQueueEnableTimeout,
    DmaIsolationBypassed,
    DmaFaultMonitoringUnavailable,
    BusMasterEnableFailed,
    InterruptIsolationUnavailable,
    InterruptRouteInstallFailed,
    MsiEnableFailed,
};

const Controller = struct {
    bar: usize,
    tx_descriptor: DmaAddress,
    tx_buffer: DmaAddress,
    rx_descriptor: DmaAddress,
    rx_buffer: DmaAddress,
    mac: [6]u8,
    tx_queue: i225_tx.Queue = .{},
    rx_head: u32 = 0,

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

const ControllerState = enum(u8) {
    unprepared,
    prepared,
    active,
};

var controller_state: u8 = @backingInt(ControllerState.unprepared);
var controller: Controller = undefined;
var active_device: pci.PCIDevice = undefined;
var published_bar_physical: u64 = 0;
var dma_windows: [DMA_WINDOW_COUNT]intel_vtd.DmaWindow = undefined;
var completed_transmit_frames: u64 = 0;
var failed_transmit_frames: u64 = 0;
var received_frames: u64 = 0;
var dropped_receive_frames: u64 = 0;
var failed_receive_polls: u64 = 0;
var pending_interrupt_causes: u32 = 0;
var empty_interrupt_streak: u8 = 0;

fn controllerState() ControllerState {
    return @fromBackingInt(@intCast(@atomicLoad(u8, &controller_state, .acquire)));
}

fn publishControllerState(value: ControllerState) void {
    @atomicStore(u8, &controller_state, @backingInt(value), .release);
}

fn controllerPrepared() bool {
    return controllerState() != .unprepared;
}

fn controllerActive() bool {
    return controllerState() == .active;
}

fn resetPendingInterruptCauses() void {
    @atomicStore(u32, &pending_interrupt_causes, 0, .monotonic);
}

pub fn prepare(device_info: pci.PCIDevice) Error!void {
    if (controllerPrepared()) return error.AlreadyPrepared;
    if (!pci.isIntelI225Lm(device_info)) return error.UnsupportedDevice;
    if (pci.busMasteringEnabled(device_info)) return error.BusMasteringNotRevoked;

    const bar_phys = barPhysicalAddress(device_info) orelse return error.BarUnmappable;
    if (bar_phys == 0) return error.BarUnmappable;
    published_bar_physical = bar_phys;
    const bar = mapBar(bar_phys);
    var pending = Controller{
        .bar = bar,
        .tx_descriptor = .{},
        .tx_buffer = .{},
        .rx_descriptor = .{},
        .rx_buffer = .{},
        .mac = readPermanentMac(bar) orelse return error.PermanentMacMissing,
    };

    pending.writeReg32(REG_IMC, 0xFFFF_FFFF);
    pending.writeReg32(REG_EIMC, 0xFFFF_FFFF);
    pending.writeReg32(REG_TXDCTL0, 0);
    if (!spinQueueState(&pending, REG_TXDCTL0, TXDCTL_QUEUE_ENABLE, false)) {
        return error.TxQueueDisableTimeout;
    }
    pending.writeReg32(REG_RXDCTL0, 0);
    if (!spinQueueState(&pending, REG_RXDCTL0, RXDCTL_QUEUE_ENABLE, false)) {
        return error.RxQueueDisableTimeout;
    }

    const frames_phys = paging.allocIdentityDmaFrames(DMA_FRAME_COUNT) orelse return error.DmaAllocationFailed;
    var committed = false;
    errdefer if (!committed) {
        pending.writeReg32(REG_TXDCTL0, 0);
        pending.writeReg32(REG_RXDCTL0, 0);
        pending.writeReg32(REG_RCTL, pending.reg32(REG_RCTL) & ~RCTL_ENABLE);
        paging.releaseIdentityDmaFrames(frames_phys, DMA_FRAME_COUNT) catch {};
    };
    const frames = DmaAddress{
        .physical = frames_phys,
        .alias = paging.directMapAddress(frames_phys) orelse return error.DmaAllocationFailed,
    };
    zeroFrames(frames.alias, DMA_FRAME_COUNT);
    pending.tx_descriptor = frames.frame(TX_DESCRIPTOR_FRAME);
    pending.tx_buffer = frames.frame(TX_BUFFER_FIRST_FRAME);
    pending.rx_descriptor = frames.frame(RX_DESCRIPTOR_FRAME);
    pending.rx_buffer = frames.frame(RX_BUFFER_FIRST_FRAME);

    configureTransmitQueue(&pending) catch |err| return err;
    configureReceiveQueue(&pending) catch |err| return err;
    pending.writeReg32(REG_CTRL_EXT, pending.reg32(REG_CTRL_EXT) | CTRL_EXT_DRIVER_LOADED);

    dma_windows = .{
        .{
            .base = pending.tx_descriptor.physical,
            .device_readable = true,
            .device_writable = true,
        },
        .{
            .base = pending.tx_buffer.physical,
            .length = i225_tx.BUFFER_REGION_BYTES,
            .device_readable = true,
            .device_writable = false,
        },
        .{
            .base = pending.rx_descriptor.physical,
            .device_readable = true,
            .device_writable = true,
        },
        .{
            .base = pending.rx_buffer.physical,
            .length = i225_rx.BUFFER_REGION_BYTES,
            .device_readable = false,
            .device_writable = true,
        },
    };
    controller = pending;
    active_device = device_info;
    completed_transmit_frames = 0;
    failed_transmit_frames = 0;
    received_frames = 0;
    dropped_receive_frames = 0;
    failed_receive_polls = 0;
    resetPendingInterruptCauses();
    empty_interrupt_streak = 0;
    publishControllerState(.prepared);
    committed = true;
}

pub fn isolationDomain() ?intel_vtd.DmaDomain {
    if (!controllerPrepared()) return null;
    return .{ .device = active_device, .windows = &dma_windows };
}

pub fn activate() Error!void {
    if (!controllerPrepared() or !intel_vtd.requesterProtected(active_device)) {
        return error.DmaIsolationBypassed;
    }
    if (!intel_vtd.faultMonitoringEnabled()) return error.DmaFaultMonitoringUnavailable;
    if (!intel_vtd.interruptIsolationEnabled()) return error.InterruptIsolationUnavailable;
    const remapped = intel_vtd.routeInterrupt(
        active_device,
        INTERRUPT_VECTOR,
        smp.irqDestinationId(),
    ) catch return error.InterruptRouteInstallFailed;
    pci.enableSingleMsi(active_device, .{
        .address = remapped.address,
        .data = remapped.data,
    }) catch return error.MsiEnableFailed;
    var msi_enabled = true;
    errdefer if (msi_enabled) pci.disableMsi(active_device) catch {};
    pci.enableMemoryBusMastering(active_device);
    if (!pci.busMasteringEnabled(active_device)) {
        pci.disableBusMastering(active_device);
        return error.BusMasterEnableFailed;
    }
    resetPendingInterruptCauses();
    empty_interrupt_streak = 0;
    _ = controller.reg32(REG_ICR);
    controller.writeReg32(REG_IMS, i225_irq.QUEUE_CAUSES);
    publishControllerState(.active);
    msi_enabled = false;
}

pub fn attached() bool {
    return controllerActive();
}

pub fn publishedBar() ?struct { physical_base: u64, length: u64 } {
    if (!controllerPrepared() or published_bar_physical == 0) return null;
    return .{ .physical_base = published_bar_physical, .length = BAR_MAP_BYTES };
}

pub fn macAddress() [6]u8 {
    if (!controllerPrepared()) return @as([6]u8, @splat(0));
    return controller.mac;
}

pub fn transmitCount() u64 {
    return completed_transmit_frames;
}

pub fn failedTransmitCount() u64 {
    return failed_transmit_frames;
}

pub fn receiveCount() u64 {
    return received_frames;
}

pub fn droppedReceiveCount() u64 {
    return dropped_receive_frames;
}

pub fn failedReceivePollCount() u64 {
    return failed_receive_polls;
}

pub fn networkWorkPending() bool {
    return networkWorkPendingAt(timer.getTicks());
}

fn networkWorkPendingAt(now_ticks: u64) bool {
    if (!controllerActive()) return false;
    if (@atomicLoad(u32, &pending_interrupt_causes, .monotonic) != 0) return true;
    return receiveCompletionReady() or transmitCompletionReady() or
        controller.tx_queue.oldestSubmissionExpired(now_ticks, TRANSMIT_TIMEOUT_TICKS);
}

pub fn nextWake() ?u64 {
    if (!controllerActive()) return null;
    return controller.tx_queue.nextWake(TRANSMIT_TIMEOUT_TICKS);
}

pub fn handleInterrupt() void {
    if (controllerPrepared()) {
        controller.writeReg32(REG_IMC, i225_irq.QUEUE_CAUSES);
        const cause = controller.reg32(REG_ICR);
        _ = @atomicRmw(
            u32,
            &pending_interrupt_causes,
            .Or,
            cause | PENDING_INTERRUPT_EVENT,
            .monotonic,
        );
    }
    x2apic.acknowledge();
}

pub fn sendPayload(destination: [6]u8, payload: []const u8) bool {
    if (!controllerActive() or !i225_frame.validDestinationMac(destination) or
        payload.len == 0 or payload.len > MAX_PAYLOAD_BYTES or !controller.linkUp())
    {
        failed_transmit_frames +%= 1;
        return false;
    }
    if (pollDmaFault()) {
        failed_transmit_frames +%= 1;
        return false;
    }
    timer.synchronize();
    const now_ticks = timer.getTicks();
    if (!serviceTransmitQueue(now_ticks)) return false;

    const descriptor_index = controller.tx_queue.reserve(now_ticks) catch {
        failed_transmit_frames +%= 1;
        return false;
    };
    const buffer_address = txBufferAddress(descriptor_index);
    const buffer: [*]u8 = @ptrFromInt(buffer_address.alias);
    const frame_len = i225_frame.buildEthernetFrame(
        buffer[0..i225_tx.BUFFER_BYTES],
        destination,
        controller.mac,
        payload,
    ) catch unreachable;

    const descriptor: *volatile i225_tx.Descriptor = @ptrFromInt(
        controller.tx_descriptor.offset(descriptor_index * i225_tx.DESCRIPTOR_BYTES).alias,
    );
    descriptor.* = i225_tx.submissionDescriptor(buffer_address.physical, frame_len) catch unreachable;
    publishDescriptor();
    controller.writeReg32(REG_TDT0, controller.tx_queue.tail);
    return true;
}

pub fn pollReceive(output: []u8) ReceiveResult {
    if (!controllerActive()) {
        failed_receive_polls +%= 1;
        return .{ .status = .failed };
    }
    if (pollDmaFault()) {
        failed_receive_polls +%= 1;
        return .{ .status = .failed };
    }
    timer.synchronize();
    if (!serviceTransmitQueue(timer.getTicks())) {
        failed_receive_polls +%= 1;
        return .{ .status = .failed };
    }
    defer rearmQueueInterrupts();
    if (!controller.linkUp()) return .{ .status = .empty };

    const descriptor_index = controller.rx_head;
    const descriptor: *volatile i225_rx.Descriptor = rxDescriptor(descriptor_index);
    var writeback = descriptor.header_or_writeback;
    if (!i225_rx.decodeCompletion(writeback).done) {
        return .{ .status = .empty };
    }
    acquireDescriptor();
    writeback = descriptor.header_or_writeback;
    defer recycleRxDescriptor(descriptor_index, descriptor);

    const completion = observeReceiveCompletion(writeback);
    const frame_len: usize = completion.length;
    if (!completion.validSingleBuffer() or frame_len < i225_frame.ETHERNET_HEADER_BYTES) {
        dropped_receive_frames +%= 1;
        return .{ .status = .dropped };
    }

    const buffer_address = rxBufferAddress(descriptor_index);
    const frame = @as([*]const u8, @ptrFromInt(buffer_address.alias))[0..frame_len];
    const view = i225_frame.parseEthernetFrame(frame, controller.mac) catch {
        dropped_receive_frames +%= 1;
        return .{ .status = .dropped };
    };
    if (view.payload.len > output.len) {
        dropped_receive_frames +%= 1;
        return .{ .status = .dropped };
    }
    @memcpy(output[0..view.payload.len], view.payload);
    received_frames +%= 1;
    return .{ .status = .frame, .length = view.payload.len };
}

fn configureTransmitQueue(pending: *Controller) Error!void {
    pending.writeReg32(REG_TDLEN0, i225_tx.RING_BYTES);
    pending.writeReg32(REG_TDBAL0, pending.tx_descriptor.physical);
    pending.writeReg32(REG_TDBAH0, 0);
    pending.writeReg32(REG_TDH0, 0);
    pending.writeReg32(REG_TDT0, 0);

    var tctl = pending.reg32(REG_TCTL);
    tctl &= ~TCTL_COLLISION_THRESHOLD_MASK;
    tctl |= TCTL_ENABLE | TCTL_PAD_SHORT_PACKET | TCTL_RETRANSMIT_LATE_COLLISION |
        TCTL_COLLISION_THRESHOLD;
    pending.writeReg32(REG_TCTL, tctl);
    pending.writeReg32(REG_TXDCTL0, TXDCTL_THRESHOLDS | TXDCTL_QUEUE_ENABLE);
    if (!spinQueueState(pending, REG_TXDCTL0, TXDCTL_QUEUE_ENABLE, true)) {
        return error.TxQueueEnableTimeout;
    }
}

fn reapTransmitCompletions() u32 {
    if (!controllerActive()) return 0;
    var reaped: u32 = 0;
    defer if (reaped != 0) noteQueueProgress();
    while (controller.tx_queue.in_flight != 0) {
        const descriptor_index = controller.tx_queue.head;
        const descriptor: *volatile i225_tx.Descriptor = @ptrFromInt(
            controller.tx_descriptor.offset(descriptor_index * i225_tx.DESCRIPTOR_BYTES).alias,
        );
        if (!i225_tx.completionDone(descriptor.olinfo_status)) return reaped;
        acquireDescriptor();
        const completion_status = descriptor.olinfo_status;
        _ = controller.tx_queue.reclaimCompleted(completion_status) orelse return reaped;
        completed_transmit_frames +%= 1;
        reaped += 1;
    }
    return reaped;
}

fn noteQueueProgress() void {
    // DMA completions may be polled before their MSI arrives. They establish
    // queue liveness even when no interrupt is pending in this service pass.
    empty_interrupt_streak = 0;
}

fn observeReceiveCompletion(writeback: u64) i225_rx.Completion {
    const completion = i225_rx.decodeCompletion(writeback);
    // A completed descriptor will be recycled even when its packet is dropped;
    // malformed packet data does not make that completion an empty interrupt.
    if (completion.done) noteQueueProgress();
    return completion;
}

fn serviceTransmitQueue(now_ticks: u64) bool {
    return serviceTransmitQueueWith(TransmitService, now_ticks);
}

const TransmitService = struct {
    fn serviceInterrupt() bool {
        return servicePendingInterrupt();
    }

    fn contain() void {
        containFailure("ZIGOS:I225:HW:TX_STALL_CONTAINED\n");
    }
};

fn serviceTransmitQueueWith(comptime Backend: type, now_ticks: u64) bool {
    if (!controllerActive() or !Backend.serviceInterrupt()) return false;
    _ = reapTransmitCompletions();
    if (!controller.tx_queue.oldestSubmissionExpired(now_ticks, TRANSMIT_TIMEOUT_TICKS)) return true;
    failed_transmit_frames +%= 1;
    Backend.contain();
    return false;
}

fn servicePendingInterrupt() bool {
    const pending = @atomicRmw(
        u32,
        &pending_interrupt_causes,
        .Xchg,
        0,
        .monotonic,
    );
    if (pending == 0) return true;
    const cause = pending & ~PENDING_INTERRUPT_EVENT;
    if (i225_irq.classify(cause) == .invalid) {
        containFailure("ZIGOS:I225:HW:INTERRUPT_CAUSE_CONTAINED\n");
        return false;
    }

    const transmit_progress = reapTransmitCompletions() != 0;
    const receive_progress = (cause & i225_irq.RECEIVE_CAUSES) != 0 and
        receiveCompletionReady();
    empty_interrupt_streak = i225_irq.nextEmptyStreak(
        empty_interrupt_streak,
        transmit_progress or receive_progress,
    );
    if (i225_irq.shouldContain(empty_interrupt_streak)) {
        containFailure("ZIGOS:I225:HW:EMPTY_INTERRUPT_STORM_CONTAINED\n");
        return false;
    }

    if ((cause & i225_irq.RECEIVE_CAUSES) != 0) {
        controller.writeReg32(REG_IMS, i225_irq.TRANSMIT_COMPLETE_CAUSE);
    } else {
        rearmQueueInterrupts();
    }
    return true;
}

fn receiveCompletionReady() bool {
    const descriptor: *volatile i225_rx.Descriptor = rxDescriptor(controller.rx_head);
    return i225_rx.decodeCompletion(descriptor.header_or_writeback).done;
}

fn transmitCompletionReady() bool {
    if (controller.tx_queue.in_flight == 0) return false;
    const descriptor: *volatile i225_tx.Descriptor = @ptrFromInt(
        controller.tx_descriptor.offset(controller.tx_queue.head * i225_tx.DESCRIPTOR_BYTES).alias,
    );
    return i225_tx.completionDone(descriptor.olinfo_status);
}

fn rearmQueueInterrupts() void {
    if (controllerActive()) controller.writeReg32(REG_IMS, i225_irq.QUEUE_CAUSES);
}

fn configureReceiveQueue(pending: *Controller) Error!void {
    var index: u32 = 0;
    while (index < i225_rx.DESCRIPTOR_COUNT) : (index += 1) {
        const descriptor: *volatile i225_rx.Descriptor = @ptrFromInt(
            pending.rx_descriptor.offset(index * i225_rx.DESCRIPTOR_BYTES).alias,
        );
        descriptor.* = i225_rx.availableDescriptor(
            pending.rx_buffer.offset(index * i225_rx.BUFFER_BYTES).physical,
        );
    }
    publishDescriptor();

    pending.writeReg32(REG_RDBAL0, pending.rx_descriptor.physical);
    pending.writeReg32(REG_RDBAH0, 0);
    pending.writeReg32(REG_RDLEN0, i225_rx.RING_BYTES);
    pending.writeReg32(REG_RDH0, 0);
    pending.writeReg32(REG_RDT0, 0);

    var srrctl = pending.reg32(REG_SRRCTL0);
    srrctl &= ~(SRRCTL_PACKET_BUFFER_MASK | SRRCTL_HEADER_BUFFER_MASK | SRRCTL_DESCRIPTOR_TYPE_MASK);
    srrctl |= SRRCTL_PACKET_BUFFER_2048 | SRRCTL_HEADER_BUFFER_256 | SRRCTL_ADVANCED_ONE_BUFFER;
    pending.writeReg32(REG_SRRCTL0, srrctl);

    var rctl = pending.reg32(REG_RCTL);
    rctl &= ~(RCTL_STORE_BAD_PACKET | RCTL_UNICAST_PROMISCUOUS | RCTL_MULTICAST_PROMISCUOUS |
        RCTL_LONG_PACKET_ENABLE | RCTL_LOOPBACK_MASK | RCTL_SIZE_256);
    rctl |= RCTL_ENABLE | RCTL_BROADCAST_ACCEPT | RCTL_STRIP_CRC;
    pending.writeReg32(REG_RCTL, rctl);

    pending.writeReg32(REG_RXDCTL0, RXDCTL_THRESHOLDS | RXDCTL_QUEUE_ENABLE);
    if (!spinQueueState(pending, REG_RXDCTL0, RXDCTL_QUEUE_ENABLE, true)) {
        return error.RxQueueEnableTimeout;
    }
    pending.writeReg32(REG_RDT0, i225_rx.DESCRIPTOR_COUNT - 1);
}

fn rxDescriptor(index: u32) *volatile i225_rx.Descriptor {
    return @ptrFromInt(controller.rx_descriptor.offset(index * i225_rx.DESCRIPTOR_BYTES).alias);
}

fn txBufferAddress(index: u32) DmaAddress {
    return controller.tx_buffer.offset(index * i225_tx.BUFFER_BYTES);
}

fn rxBufferAddress(index: u32) DmaAddress {
    return controller.rx_buffer.offset(index * i225_rx.BUFFER_BYTES);
}

fn recycleRxDescriptor(index: u32, descriptor: *volatile i225_rx.Descriptor) void {
    descriptor.* = i225_rx.availableDescriptor(rxBufferAddress(index).physical);
    publishDescriptor();
    controller.rx_head = i225_rx.nextIndex(index);
    controller.writeReg32(REG_RDT0, index);
}

fn pollDmaFault() bool {
    if (!intel_vtd.faultMonitoringEnabled()) {
        containFailure("ZIGOS:I225:HW:FAULT_MONITOR_UNAVAILABLE\n");
        return true;
    }
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
    controller.writeReg32(REG_IMC, 0xFFFF_FFFF);
    controller.writeReg32(REG_EIMC, 0xFFFF_FFFF);
    publishControllerState(.prepared);
    pci.disableMsi(active_device) catch {};
    pci.disableBusMastering(active_device);
    controller.writeReg32(REG_TXDCTL0, 0);
    controller.writeReg32(REG_RXDCTL0, 0);
    controller.writeReg32(REG_RCTL, controller.reg32(REG_RCTL) & ~RCTL_ENABLE);
    console.print(marker);
}

fn barPhysicalAddress(device_info: pci.PCIDevice) ?usize {
    return (pci.memoryBar0(device_info) orelse return null).address;
}

fn mapBar(physical: usize) usize {
    var offset: u32 = 0;
    while (offset < BAR_MAP_BYTES) : (offset += PAGE_SIZE) {
        paging.mapKernelBorrowedPage(
            mmio_windows.intel_i225.base + offset,
            physical + offset,
            paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE,
        );
    }
    return mmio_windows.intel_i225.base;
}

fn readPermanentMac(bar: usize) ?[6]u8 {
    const ral = @as(*volatile u32, @ptrFromInt(bar + REG_RAL0)).*;
    const rah = @as(*volatile u32, @ptrFromInt(bar + REG_RAH0)).*;
    if ((rah & RAH_ADDRESS_VALID) == 0) return null;
    const mac = i225_frame.decodeMac(ral, rah);
    if (!i225_frame.validUnicastMac(mac)) return null;
    return mac;
}

fn spinQueueState(pending: *const Controller, register: usize, mask: u32, want_enabled: bool) bool {
    const deadline = tsc_clock.afterMilliseconds(QUEUE_STATE_TIMEOUT_MILLISECONDS);
    while (!deadline.expired()) {
        if (((pending.reg32(register) & mask) != 0) == want_enabled) return true;
        spin.hint();
    }
    return false;
}

fn zeroFrames(base: usize, count: u32) void {
    @memset(@as([*]u8, @ptrFromInt(base))[0 .. @as(usize, count) * PAGE_SIZE], 0);
}

fn publishDescriptor() void {
    asm volatile ("mfence" ::: .{ .memory = true });
}

fn acquireDescriptor() void {
    asm volatile ("lfence" ::: .{ .memory = true });
}

test "I225 polled transmit completions preserve liveness across delayed interrupts" {
    const saved_state = controllerState();
    const saved_controller: ?Controller = if (controllerPrepared()) controller else null;
    const saved_completed = completed_transmit_frames;
    const saved_streak = empty_interrupt_streak;
    defer {
        if (saved_controller) |previous| controller = previous;
        publishControllerState(saved_state);
        completed_transmit_frames = saved_completed;
        empty_interrupt_streak = saved_streak;
    }
    var descriptors = std.mem.zeroes([i225_tx.DESCRIPTOR_COUNT]i225_tx.Descriptor);
    controller = .{
        .bar = 0,
        .tx_descriptor = .{ .physical = 0x1000, .alias = @intFromPtr(&descriptors) },
        .tx_buffer = .{},
        .rx_descriptor = .{},
        .rx_buffer = .{},
        .mac = @splat(0),
    };
    publishControllerState(.active);
    empty_interrupt_streak = i225_irq.EMPTY_INTERRUPT_LIMIT - 1;
    for (0..i225_tx.DESCRIPTOR_COUNT * 2) |iteration| {
        const index = try controller.tx_queue.reserve(iteration);
        descriptors[index] = try i225_tx.submissionDescriptor(0x2000, 64);
        const prior_streak = empty_interrupt_streak;
        try std.testing.expectEqual(@as(u32, 0), reapTransmitCompletions());
        try std.testing.expectEqual(prior_streak, empty_interrupt_streak);
        descriptors[index].olinfo_status |= 1;
        try std.testing.expectEqual(@as(u32, 1), reapTransmitCompletions());
        try std.testing.expectEqual(@as(u8, 0), empty_interrupt_streak);
        // The subsequent MSI has no remaining descriptor to reclaim. Each
        // actual completion breaks the streak before this delayed interrupt.
        empty_interrupt_streak = i225_irq.nextEmptyStreak(empty_interrupt_streak, false);
        try std.testing.expect(!i225_irq.shouldContain(empty_interrupt_streak));
        try std.testing.expectEqual(@as(u8, 1), empty_interrupt_streak);
    }
    try std.testing.expectEqual(saved_completed + i225_tx.DESCRIPTOR_COUNT * 2, completed_transmit_frames);
    for (0..i225_irq.EMPTY_INTERRUPT_LIMIT - 1) |_| {
        try std.testing.expectEqual(@as(u32, 0), reapTransmitCompletions());
        empty_interrupt_streak = i225_irq.nextEmptyStreak(empty_interrupt_streak, false);
    }
    try std.testing.expect(i225_irq.shouldContain(empty_interrupt_streak));
}

test "I225 receive progress includes dropped descriptors before delayed interrupts" {
    const saved_streak = empty_interrupt_streak;
    defer empty_interrupt_streak = saved_streak;
    empty_interrupt_streak = i225_irq.EMPTY_INTERRUPT_LIMIT - 1;
    try std.testing.expect(!observeReceiveCompletion(@as(u64, 64) << 32).done);
    try std.testing.expectEqual(i225_irq.EMPTY_INTERRUPT_LIMIT - 1, empty_interrupt_streak);

    for (0..i225_rx.DESCRIPTOR_COUNT * 2) |iteration| {
        const dropped = iteration % 2 != 0;
        const writeback = @as(u64, if (dropped) 0x8000_0003 else 3) | (@as(u64, 64) << 32);
        const completion = observeReceiveCompletion(writeback);
        try std.testing.expect(completion.done);
        try std.testing.expectEqual(!dropped, completion.validSingleBuffer());
        try std.testing.expectEqual(@as(u8, 0), empty_interrupt_streak);
        empty_interrupt_streak = i225_irq.nextEmptyStreak(empty_interrupt_streak, false);
        try std.testing.expect(!i225_irq.shouldContain(empty_interrupt_streak));
        try std.testing.expectEqual(@as(u8, 1), empty_interrupt_streak);
    }
    for (0..i225_irq.EMPTY_INTERRUPT_LIMIT - 1) |_| {
        _ = observeReceiveCompletion(0);
        empty_interrupt_streak = i225_irq.nextEmptyStreak(empty_interrupt_streak, false);
    }
    try std.testing.expect(i225_irq.shouldContain(empty_interrupt_streak));
}

test "I225 idle transmit deadlines service polled completion and contain one stalled submission" {
    const Backend = struct {
        var contained: usize = 0;

        fn serviceInterrupt() bool {
            return servicePendingInterrupt();
        }

        fn contain() void {
            contained += 1;
            // The policy test replaces only privileged containment operations.
            // Published descriptors stay owned and pinned after containment.
            publishControllerState(.prepared);
        }
    };
    const saved_state = controllerState();
    const saved_controller: ?Controller = if (controllerPrepared()) controller else null;
    const saved_completed = completed_transmit_frames;
    const saved_failed = failed_transmit_frames;
    const saved_pending = @atomicLoad(u32, &pending_interrupt_causes, .monotonic);
    const saved_streak = empty_interrupt_streak;
    defer {
        if (saved_controller) |previous| controller = previous;
        publishControllerState(saved_state);
        completed_transmit_frames = saved_completed;
        failed_transmit_frames = saved_failed;
        @atomicStore(u32, &pending_interrupt_causes, saved_pending, .monotonic);
        empty_interrupt_streak = saved_streak;
    }
    var registers = std.mem.zeroes([BAR_MAP_BYTES / @sizeOf(u32)]u32);
    var tx = std.mem.zeroes([i225_tx.DESCRIPTOR_COUNT]i225_tx.Descriptor);
    var rx = std.mem.zeroes([i225_rx.DESCRIPTOR_COUNT]i225_rx.Descriptor);
    controller = .{
        .bar = @intFromPtr(&registers),
        .tx_descriptor = .{ .physical = 0x1000, .alias = @intFromPtr(&tx) },
        .tx_buffer = .{},
        .rx_descriptor = .{ .physical = 0x2000, .alias = @intFromPtr(&rx) },
        .rx_buffer = .{},
        .mac = @splat(0),
    };
    Backend.contained = 0;
    resetPendingInterruptCauses();
    publishControllerState(.active);
    empty_interrupt_streak = i225_irq.EMPTY_INTERRUPT_LIMIT - 1;
    try std.testing.expect(nextWake() == null);
    const first = try controller.tx_queue.reserve(107);
    tx[first] = try i225_tx.submissionDescriptor(0x3000, 64);
    try std.testing.expectEqual(@as(?u64, 207), nextWake());
    try std.testing.expect(!networkWorkPendingAt(206));
    // Lost or delayed MSI does not hide a completion or force periodic polling.
    tx[first].olinfo_status |= 1;
    try std.testing.expect(networkWorkPendingAt(150));
    try std.testing.expect(serviceTransmitQueueWith(Backend, 150));
    try std.testing.expect(nextWake() == null);
    try std.testing.expect(!networkWorkPendingAt(150));
    try std.testing.expectEqual(@as(u8, 0), empty_interrupt_streak);
    @atomicStore(u32, &pending_interrupt_causes, PENDING_INTERRUPT_EVENT, .monotonic);
    try std.testing.expect(serviceTransmitQueueWith(Backend, 151));
    try std.testing.expectEqual(@as(u8, 1), empty_interrupt_streak);
    try std.testing.expectEqual(@as(usize, 0), Backend.contained);

    const stalled = try controller.tx_queue.reserve(200);
    tx[stalled] = try i225_tx.submissionDescriptor(0x3000, 64);
    try std.testing.expectEqual(@as(?u64, 300), nextWake());
    try std.testing.expect(!networkWorkPendingAt(299));
    try std.testing.expect(networkWorkPendingAt(300));
    try std.testing.expect(!serviceTransmitQueueWith(Backend, 300));
    try std.testing.expectEqual(@as(usize, 1), Backend.contained);
    try std.testing.expectEqual(saved_failed + 1, failed_transmit_frames);
    try std.testing.expectEqual(@as(u32, 1), controller.tx_queue.in_flight);
    try std.testing.expect(nextWake() == null);
    try std.testing.expect(!networkWorkPendingAt(300));
    try std.testing.expect(!serviceTransmitQueueWith(Backend, 301));
    try std.testing.expectEqual(@as(usize, 1), Backend.contained);
}
