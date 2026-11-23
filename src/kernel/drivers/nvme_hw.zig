const console = @import("../utils/console.zig");
const spin = @import("../utils/spin.zig");
const x86 = @import("../../arch/x86.zig");
const timer = @import("../timer/timer.zig");
const tsc_clock = @import("../timer/tsc_clock.zig");
const interrupt_context = @import("../interrupts/context.zig");
const x2apic = @import("../interrupts/x2apic.zig");
const mmio_windows = @import("../memory/mmio_windows.zig");
const paging = @import("../memory/paging64.zig");
const intel_vtd = @import("../platform/intel_vtd.zig");
const numfmt = @import("../utils/numfmt.zig");
const device_isolation = @import("device_isolation.zig");
const dma_enforcement = @import("dma_enforcement.zig");
const nvme_completion = @import("nvme_completion.zig");
const nvme_interrupt = @import("nvme_interrupt.zig");
const nvme_pipeline = @import("nvme_pipeline.zig");
const nvme_poll = @import("nvme_poll.zig");
const nvme_operation = @import("nvme_operation.zig");
const nvme_prp = @import("nvme_prp.zig");
const nvme_timing = @import("nvme_timing.zig");
const pci = @import("pci.zig");
const dataplane_handoff = @import("../../native/drivers/dataplane_handoff.zig");
const smp = @import("../smp.zig");
const cooperative = @import("../../native/task/cooperative_worker.zig");

pub const SECTOR_BYTES: usize = 512;
pub const INTERRUPT_VECTOR = nvme_interrupt.INTERRUPT_VECTOR;
const PAGE_SIZE: u32 = 4096;

const IO_PIPELINE_DEPTH: usize = nvme_pipeline.DEPTH;
const BOUNCE_FIRST_FRAME: u32 = 4;
const BOUNCE_SLOT_PAGE_COUNT: u32 = @intCast(nvme_prp.MAX_DATA_PAGES);
const BOUNCE_PAGE_COUNT: u32 = BOUNCE_SLOT_PAGE_COUNT * @as(u32, IO_PIPELINE_DEPTH);
const PRP_LIST_FIRST_FRAME: u32 = BOUNCE_FIRST_FRAME + BOUNCE_PAGE_COUNT;
const PRP_LIST_PAGE_COUNT: u32 = IO_PIPELINE_DEPTH;
const BOUNCE_SECTORS: usize = nvme_prp.MAX_TRANSFER_BYTES / SECTOR_BYTES;

const REG_CAP: usize = 0x00;
const REG_VS: usize = 0x08;
const REG_CRTO: usize = 0x68;
const REG_CC: usize = 0x14;
const REG_CSTS: usize = 0x1C;
const REG_AQA: usize = 0x24;
const REG_ASQ: usize = 0x28;
const REG_ACQ: usize = 0x30;
const REG_DOORBELL_BASE: usize = 0x1000;

const CC_EN: u32 = 1 << 0;
const CC_CSS_NVM: u32 = 0 << 4;
const CC_MPS_4K: u32 = 0 << 7;
const CC_AMS_RR: u32 = 0 << 11;
const CC_IOSQES: u32 = 6 << 16;
const CC_IOCQES: u32 = 4 << 20;

const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;

const ADMIN_QUEUE_ENTRIES: u32 = 32;
const SQ_ENTRY_BYTES: usize = 64;
const CQ_ENTRY_BYTES: usize = 16;
const BAR_MAP_BYTES: u32 = 0x2000;
const MSIX_ENTRY_WINDOW: usize = mmio_windows.nvme.base + BAR_MAP_BYTES;
const MSIX_ENTRY_BYTES: u64 = 16;

comptime {
    if (@as(usize, BAR_MAP_BYTES) + PAGE_SIZE > mmio_windows.nvme.bytes) {
        @compileError("NVMe BAR and MSI-X entry mappings exceed their reserved MMIO window");
    }
}

pub const Error = error{
    Busy,
    InterruptContext,
    WrongCpu,
    Cancelled,
    AuthorityRevoked,
    BarUnmappable,
    ControllerResetTimeout,
    ControllerEnableTimeout,
    ControllerFatal,
    QueueAllocationFailed,
    BusMasteringNotRevoked,
    BusMasterEnableFailed,
    CommandTimeout,
    CommandFailed,
    CompletionOwnershipMismatch,
    TransferTooLarge,
    EmptyTransfer,
    LbaOutOfRange,
    NamespaceMissing,
    UnsupportedLbaFormat,
    DmaIsolationBypassed,
    DmaFault,
    InterruptIsolationUnavailable,
    InterruptRouteInstallFailed,
    MsiEnableFailed,
    DmaIsolationPlanInvalid,
};

const ADMIN_OPC_CREATE_IO_SQ: u32 = 0x01;
const ADMIN_OPC_CREATE_IO_CQ: u32 = 0x05;
const ADMIN_OPC_IDENTIFY: u32 = 0x06;

const IDENTIFY_CNS_NAMESPACE: u32 = 0x00;

const NVM_OPC_FLUSH: u32 = 0x00;
const NVM_OPC_WRITE: u32 = 0x01;
const NVM_OPC_READ: u32 = 0x02;

const IO_QUEUE_ID: u16 = 1;
const IO_QUEUE_ENTRIES: u32 = 32;
const DMA_FRAME_COUNT: u32 = PRP_LIST_FIRST_FRAME + PRP_LIST_PAGE_COUNT;
const DMA_WINDOW_COUNT: usize = 6;

const DmaAddress = struct {
    physical: u32 = 0,
    alias: usize = 0,
};

const Queue = struct {
    sq: DmaAddress,
    cq: DmaAddress,
    entries: u32,
    qid: u16,
    sq_tail: u32 = 0,
    cq_head: u32 = 0,
    phase: u1 = 1,
    next_cid: u16 = 0,
};

const OutstandingCommand = struct {
    cid: u16,
    deadline: tsc_clock.Deadline,
};
const TransferSlots = nvme_pipeline.SlotSet(OutstandingCommand);

const DmaFrames = struct {
    base: DmaAddress,

    fn frame(self: DmaFrames, index: u32) DmaAddress {
        return .{
            .physical = self.base.physical + index * PAGE_SIZE,
            .alias = self.base.alias + @as(usize, index) * PAGE_SIZE,
        };
    }

    fn windows(self: DmaFrames) [DMA_WINDOW_COUNT]intel_vtd.DmaWindow {
        return .{
            .{ .base = self.frame(0).physical, .device_readable = true, .device_writable = false },
            .{ .base = self.frame(1).physical, .device_readable = false, .device_writable = true },
            .{ .base = self.frame(2).physical, .device_readable = true, .device_writable = false },
            .{ .base = self.frame(3).physical, .device_readable = false, .device_writable = true },
            .{
                .base = self.frame(BOUNCE_FIRST_FRAME).physical,
                .length = @intCast(nvme_prp.MAX_TRANSFER_BYTES * IO_PIPELINE_DEPTH),
                .device_readable = true,
                .device_writable = true,
            },
            .{
                .base = self.frame(PRP_LIST_FIRST_FRAME).physical,
                .length = PAGE_SIZE * PRP_LIST_PAGE_COUNT,
                .device_readable = true,
                .device_writable = false,
            },
        };
    }

    fn bounce(self: DmaFrames, slot: usize) DmaAddress {
        return self.frame(BOUNCE_FIRST_FRAME + @as(u32, @intCast(slot)) * BOUNCE_SLOT_PAGE_COUNT);
    }

    fn prpList(self: DmaFrames, slot: usize) DmaAddress {
        return self.frame(PRP_LIST_FIRST_FRAME + @as(u32, @intCast(slot)));
    }
};

pub const Controller = struct {
    device: pci.PCIDevice,
    bar: usize,
    doorbell_stride: usize,
    admin: Queue,
    io: Queue = undefined,
    io_ready: bool = false,
    nsid: u32 = 1,
    lba_bytes: u32 = SECTOR_BYTES,
    namespace_sectors: u64 = 0,
    io_prp_lists: [IO_PIPELINE_DEPTH]DmaAddress = @as([IO_PIPELINE_DEPTH]DmaAddress, @splat(.{})),

    fn reg32(self: *const Controller, offset: usize) u32 {
        return @as(*volatile u32, @ptrFromInt(self.bar + offset)).*;
    }

    fn writeReg32(self: *const Controller, offset: usize, value: u32) void {
        @as(*volatile u32, @ptrFromInt(self.bar + offset)).* = value;
    }

    fn writeReg64(self: *const Controller, offset: usize, value: u64) void {
        @as(*volatile u32, @ptrFromInt(self.bar + offset)).* = @truncate(value & 0xFFFF_FFFF);
        @as(*volatile u32, @ptrFromInt(self.bar + offset + 4)).* = @truncate(value >> 32);
    }

    pub fn capabilities(self: *const Controller) u64 {
        const low: u64 = self.reg32(REG_CAP);
        const high: u64 = self.reg32(REG_CAP + 4);
        return low | (high << 32);
    }

    pub fn version(self: *const Controller) u32 {
        return self.reg32(REG_VS);
    }

    pub fn ready(self: *const Controller) bool {
        return (self.reg32(REG_CSTS) & CSTS_RDY) != 0;
    }

    pub fn fatal(self: *const Controller) bool {
        return (self.reg32(REG_CSTS) & CSTS_CFS) != 0;
    }

    fn readyTimeoutMilliseconds(self: *const Controller) u64 {
        return nvme_timing.readyTimeoutMilliseconds(self.capabilities(), self.reg32(REG_CRTO));
    }
};

fn mapBar(phys: u64) Error!usize {
    paging.mapKernelDeviceRange(mmio_windows.nvme.base, phys, BAR_MAP_BYTES, true) catch return error.BarUnmappable;
    return mmio_windows.nvme.base;
}

fn doorbellStride(cap: u64) usize {
    const dstrd: u5 = @intCast((cap >> 32) & 0xF);
    return @as(usize, 4) << dstrd;
}

inline fn mappedDoorbellsFit(stride: usize) bool {
    return REG_DOORBELL_BASE + (2 * IO_QUEUE_ID + 1) * stride + @sizeOf(u32) <= BAR_MAP_BYTES;
}

test "NVMe rejects CAP doorbell strides outside the owned BAR window" {
    const std = @import("std");
    for (0..16) |dstrd| {
        const capability = @as(u64, @intCast(dstrd)) << 32;
        try std.testing.expectEqual(dstrd <= 8, mappedDoorbellsFit(doorbellStride(capability)));
    }
}

fn spinUntilReady(controller: *const Controller, want_ready: bool) bool {
    const deadline = tsc_clock.afterMilliseconds(controller.readyTimeoutMilliseconds());
    while (!deadline.expired()) {
        if (controller.fatal()) return false;
        if (controller.ready() == want_ready) return true;
        spin.hint();
    }
    return false;
}

fn prepare(dev: pci.PCIDevice, bar_phys: u64, frames: DmaFrames) Error!Controller {
    const bar = try mapBar(bar_phys);

    var controller = Controller{
        .device = dev,
        .bar = bar,
        .doorbell_stride = doorbellStride((@as(u64, @as(*volatile u32, @ptrFromInt(bar + REG_CAP + 4)).*) << 32) |
            @as(u64, @as(*volatile u32, @ptrFromInt(bar + REG_CAP)).*)),
        .admin = undefined,
    };
    if (!mappedDoorbellsFit(controller.doorbell_stride)) return error.BarUnmappable;

    controller.writeReg32(REG_CC, controller.reg32(REG_CC) & ~CC_EN);
    if (!spinUntilReady(&controller, false)) {
        if (controller.fatal()) return error.ControllerFatal;
        return error.ControllerResetTimeout;
    }

    const sq = frames.frame(0);
    const cq = frames.frame(1);
    zeroFrame(sq.alias);
    zeroFrame(cq.alias);
    controller.admin = .{
        .sq = sq,
        .cq = cq,
        .entries = ADMIN_QUEUE_ENTRIES,
        .qid = 0,
    };

    const aqa = ((ADMIN_QUEUE_ENTRIES - 1) << 16) | (ADMIN_QUEUE_ENTRIES - 1);
    controller.writeReg32(REG_AQA, aqa);
    controller.writeReg64(REG_ASQ, sq.physical);
    controller.writeReg64(REG_ACQ, cq.physical);

    return controller;
}

inline fn enable(self: *Controller) Error!void {
    self.writeReg32(REG_CC, CC_CSS_NVM | CC_MPS_4K | CC_AMS_RR | CC_IOSQES | CC_IOCQES | CC_EN);
    if (!spinUntilReady(self, true)) {
        if (self.fatal()) return error.ControllerFatal;
        return error.ControllerEnableTimeout;
    }
}

fn sqDoorbell(self: *const Controller, qid: u16) usize {
    return REG_DOORBELL_BASE + (2 * @as(usize, qid)) * self.doorbell_stride;
}

fn cqDoorbell(self: *const Controller, qid: u16) usize {
    return REG_DOORBELL_BASE + (2 * @as(usize, qid) + 1) * self.doorbell_stride;
}

fn submitCommand(self: *Controller, queue: *Queue, command: *const [16]u32) OutstandingCommand {
    const cid = queue.next_cid;
    queue.next_cid +%= 1;

    const sq_entry: [*]volatile u32 = @ptrFromInt(queue.sq.alias + queue.sq_tail * SQ_ENTRY_BYTES);
    var i: usize = 0;
    while (i < 16) : (i += 1) sq_entry[i] = command[i];
    sq_entry[0] = (command[0] & 0x0000_FFFF) | (@as(u32, cid) << 16);
    publishSubmission();

    queue.sq_tail = (queue.sq_tail + 1) % queue.entries;
    self.writeReg32(sqDoorbell(self, queue.qid), queue.sq_tail);

    return .{
        .cid = cid,
        .deadline = tsc_clock.afterMilliseconds(nvme_timing.COMMAND_TIMEOUT_MILLISECONDS),
    };
}

fn waitForAnyCompletion(
    self: *Controller,
    queue: *Queue,
    outstanding: []const OutstandingCommand,
) Error!u16 {
    const wait_with_interrupt = nvme_interrupt.mayIdleWait(
        queue.qid,
        interruptsActive(),
        interrupt_context.active(),
    );
    var io = CompletionIo{ .controller = self, .queue = queue, .restore_interrupt_mask = wait_with_interrupt and !x86.interruptsEnabled() };
    const worker = if (queue.qid != 0 and !interrupt_context.active()) cooperative.current() else null;
    return nvme_poll.wait(&io, queue, outstanding, wait_with_interrupt, worker);
}

const CompletionIo = struct {
    controller: *Controller,
    queue: *Queue,
    restore_interrupt_mask: bool,

    fn entry(self: *@This(), head: u32) [*]volatile u32 {
        return @ptrFromInt(self.queue.cq.alias + head * CQ_ENTRY_BYTES);
    }
    pub fn expired(_: *@This(), deadline: tsc_clock.Deadline) bool {
        return deadline.expired();
    }
    pub fn fatal(self: *@This()) bool {
        return self.controller.fatal();
    }
    pub fn checkDma(self: *@This()) nvme_poll.Error!void {
        switch (device_isolation.pollFault(self.controller.device)) {
            .clear, .monitoring_unavailable => {},
            .fail_closed, .fault => return error.DmaFault,
        }
    }
    pub fn status(self: *@This(), head: u32) u32 {
        return self.entry(head)[3];
    }
    pub fn submission(self: *@This(), head: u32) u32 {
        return self.entry(head)[2];
    }
    pub fn acquireCompletion(_: *@This()) void {
        completionFence();
    }
    pub fn acknowledge(self: *@This(), head: u32) void {
        self.controller.writeReg32(cqDoorbell(self.controller, self.queue.qid), head);
    }
    pub fn pause(_: *@This()) void {
        spin.hint();
    }
    pub fn idle(self: *@This(), queue: *Queue) void {
        timer.armSchedulerTick();
        x86.cli();
        if (nvme_completion.phase(self.status(queue.cq_head)) == queue.phase) {
            if (!self.restore_interrupt_mask) x86.sti();
            return;
        }
        x86.stiHlt();
        if (self.restore_interrupt_mask) x86.cli();
    }
};

fn submit(self: *Controller, queue: *Queue, command: *const [16]u32) Error!void {
    const outstanding = [_]OutstandingCommand{submitCommand(self, queue, command)};
    _ = try waitForAnyCompletion(self, queue, &outstanding);
}

pub fn createIoQueues(self: *Controller, frames: DmaFrames) Error!void {
    const cq = frames.frame(3);
    const sq = frames.frame(2);
    zeroFrame(cq.alias);
    zeroFrame(sq.alias);

    var create_cq = @as([16]u32, @splat(0));
    create_cq[0] = ADMIN_OPC_CREATE_IO_CQ;
    create_cq[6] = cq.physical;
    create_cq[10] = ((IO_QUEUE_ENTRIES - 1) << 16) | IO_QUEUE_ID;
    create_cq[11] = nvme_interrupt.createCompletionQueueControl();
    try submit(self, &self.admin, &create_cq);

    var create_sq = @as([16]u32, @splat(0));
    create_sq[0] = ADMIN_OPC_CREATE_IO_SQ;
    create_sq[6] = sq.physical;
    create_sq[10] = ((IO_QUEUE_ENTRIES - 1) << 16) | IO_QUEUE_ID;
    create_sq[11] = (@as(u32, IO_QUEUE_ID) << 16) | 1;
    try submit(self, &self.admin, &create_sq);

    self.io = .{
        .sq = sq,
        .cq = cq,
        .entries = IO_QUEUE_ENTRIES,
        .qid = IO_QUEUE_ID,
    };
    self.io_ready = true;
}

fn submitIoCommand(
    self: *Controller,
    opcode: u32,
    lba: u64,
    buffer: DmaAddress,
    prp_list: DmaAddress,
    sector_count: u16,
) Error!OutstandingCommand {
    if (!self.io_ready) return error.NamespaceMissing;

    if (sector_count == 0) return error.EmptyTransfer;
    const transfer_bytes = @as(usize, sector_count) * self.lba_bytes;
    const prp = nvme_prp.plan(buffer.physical, prp_list.physical, transfer_bytes) catch |err| switch (err) {
        error.EmptyTransfer => return error.EmptyTransfer,
        error.TransferTooLarge => return error.TransferTooLarge,
        else => return error.DmaIsolationBypassed,
    };
    const prp_entries: [*]volatile u64 = @ptrFromInt(prp_list.alias);
    for (0..prp.list_entry_count) |index| {
        prp_entries[index] = prp.listEntryAddress(index) orelse return error.DmaIsolationBypassed;
    }

    if (lba > self.namespace_sectors or self.namespace_sectors - lba < sector_count) return error.LbaOutOfRange;
    var cmd = @as([16]u32, @splat(0));
    cmd[0] = opcode;
    cmd[1] = self.nsid;
    cmd[6] = @truncate(prp.buffer_address);
    cmd[7] = @truncate(prp.buffer_address >> 32);
    cmd[8] = @truncate(prp.second_pointer);
    cmd[9] = @truncate(prp.second_pointer >> 32);
    cmd[10] = @truncate(lba & 0xFFFF_FFFF);
    cmd[11] = @truncate(lba >> 32);
    cmd[12] = @as(u32, sector_count) - 1;
    return submitCommand(self, &self.io, &cmd);
}

fn waitForIoCommand(self: *Controller, command: OutstandingCommand) Error!void {
    const outstanding = [_]OutstandingCommand{command};
    _ = try waitForAnyCompletion(self, &self.io, &outstanding);
}

fn flush(self: *Controller) Error!void {
    if (!self.io_ready) return error.NamespaceMissing;
    var command = @as([16]u32, @splat(0));
    command[0] = NVM_OPC_FLUSH;
    command[1] = self.nsid;
    try submit(self, &self.io, &command);
}

fn zeroFrame(alias: usize) void {
    const bytes: [*]u8 = @ptrFromInt(alias);
    @memset(bytes[0..PAGE_SIZE], 0);
}

fn publishSubmission() void {
    asm volatile ("mfence" ::: .{ .memory = true });
}

fn completionFence() void {
    asm volatile ("lfence" ::: .{ .memory = true });
}

var active_controller: Controller = undefined;
var active_device: pci.PCIDevice = undefined;
var active_present: bool = false;
var operation_lease = nvme_operation.Lease{};
var bounce: [IO_PIPELINE_DEPTH]DmaAddress = @as([IO_PIPELINE_DEPTH]DmaAddress, @splat(.{}));
var io_interrupts_active: bool = false;
// DMA frames are allocated once, before VT-d enforcement, and stay pinned:
// the enforced isolation domain names exactly these windows.
var dma_frames: ?DmaFrames = null;
var dma_device_id: u64 = 0;
var dma_windows: [DMA_WINDOW_COUNT]intel_vtd.DmaWindow = undefined;
var msix_entry_physical: ?u64 = null;

fn interruptsActive() bool {
    return @atomicLoad(bool, &io_interrupts_active, .acquire);
}

fn publishInterruptsActive(value: bool) void {
    @atomicStore(bool, &io_interrupts_active, value, .release);
}

pub fn attached() bool {
    return active_present;
}

pub fn attachedDeviceId() ?u64 {
    if (!active_present) return null;
    return pci.stableDeviceId(active_device);
}

fn runtimeIoPermitted() bool {
    const device_id = attachedDeviceId() orelse return false;
    if (!dataplane_handoff.allowsKernelRuntimeIo(device_id)) return false;
    // An accepted command still drains after revocation. Only refill and new
    // operations consult the immutable submit snapshot's live broker authority.
    return !dataplane_handoff.claimed(device_id) or owned_submit_authority(device_id);
}

/// Reports whether the owner's current submission still holds live broker
/// authority for a claimed controller. Claimed I/O is refused until the
/// storage driver port installs its check.
var owned_submit_authority: *const fn (device_id: u64) bool = denyOwnedSubmit;

fn denyOwnedSubmit(_: u64) bool {
    return false;
}

pub fn bindOwnedSubmitAuthority(check: *const fn (device_id: u64) bool) void {
    owned_submit_authority = check;
}

/// Route the I/O completion queue's single interrupt. MSI-X entry 0 is
/// preferred when its table lies in the admitted BAR0 aperture; MSI is the
/// fallback for controllers without one.
pub fn activateInterrupts() Error!void {
    const identity = try beginOperation();
    defer operation_lease.release(identity);
    if (!active_present) return error.NamespaceMissing;
    if (interruptsActive()) return;
    if (!intel_vtd.interruptIsolationEnabled()) return error.InterruptIsolationUnavailable;
    const target: device_isolation.MessageTarget = if (msix_entry_physical) |physical| target: {
        const page = physical & ~@as(u64, PAGE_SIZE - 1);
        paging.mapKernelDeviceRange(MSIX_ENTRY_WINDOW, page, PAGE_SIZE, true) catch return error.MsiEnableFailed;
        break :target .{ .msix = @ptrFromInt(MSIX_ENTRY_WINDOW + @as(usize, @intCast(physical - page))) };
    } else .msi;
    device_isolation.routeInterrupt(active_device, INTERRUPT_VECTOR, target) catch |err| return switch (err) {
        error.InterruptRouteInstallFailed => error.InterruptRouteInstallFailed,
        else => error.MsiEnableFailed,
    };
    publishInterruptsActive(true);
}

pub fn handleInterrupt() void {
    x2apic.acknowledge();
}

/// Locate MSI-X entry 0 inside the sized BAR0 aperture, beyond the register
/// mapping, or report that the controller must use MSI.
fn msixEntryPhysical(table: pci.MsixTable, aperture: pci.BarAperture) ?u64 {
    if (table.bar_index != 0 or table.offset % MSIX_ENTRY_BYTES != 0 or
        table.offset < BAR_MAP_BYTES or table.offset + MSIX_ENTRY_BYTES > aperture.length) return null;
    return aperture.address + table.offset;
}

test "NVMe MSI-X entry zero must lie in BAR0 outside the register mapping" {
    const std = @import("std");
    const aperture = pci.BarAperture{ .address = 0xFE00_0000, .length = 0x4000 };
    try std.testing.expectEqual(@as(?u64, 0xFE00_2000), msixEntryPhysical(.{ .bar_index = 0, .offset = 0x2000, .entries = 65 }, aperture));
    try std.testing.expectEqual(@as(?u64, null), msixEntryPhysical(.{ .bar_index = 4, .offset = 0x2000, .entries = 65 }, aperture));
    try std.testing.expectEqual(@as(?u64, null), msixEntryPhysical(.{ .bar_index = 0, .offset = 0x1000, .entries = 65 }, aperture));
    try std.testing.expectEqual(@as(?u64, null), msixEntryPhysical(.{ .bar_index = 0, .offset = 0x3FF8, .entries = 1 }, aperture));
}

fn identifyNamespace(self: *Controller, buffer: DmaAddress) Error!void {
    zeroFrame(buffer.alias);
    var cmd = @as([16]u32, @splat(0));
    cmd[0] = ADMIN_OPC_IDENTIFY;
    cmd[1] = self.nsid;
    cmd[6] = buffer.physical;
    cmd[10] = IDENTIFY_CNS_NAMESPACE;
    try submit(self, &self.admin, &cmd);
    const words: [*]volatile u32 = @ptrFromInt(buffer.alias);
    const nsze_low: u64 = words[0];
    const nsze_high: u64 = words[1];
    const nsze = nsze_low | (nsze_high << 32);
    if (nsze == 0) return error.NamespaceMissing;

    const flbas: u32 = (words[6] >> 16) & 0xFF;
    const fmt_index: u32 = flbas & 0x0F;
    const lbaf: u32 = words[32 + fmt_index];
    const lbads: u32 = (lbaf >> 16) & 0xFF;
    if (lbads < 9 or lbads > 12) return error.UnsupportedLbaFormat;
    const lba_bytes: u32 = @as(u32, 1) << @as(u5, @intCast(lbads));
    if (lba_bytes != SECTOR_BYTES) return error.UnsupportedLbaFormat;

    self.lba_bytes = lba_bytes;
    self.namespace_sectors = nsze;
}

fn issueFaultProbe(self: *Controller, guard_phys: u32) void {
    const queue = &self.admin;
    const cid = queue.next_cid;
    queue.next_cid +%= 1;

    const command = faultProbeCommand(self.nsid, guard_phys);

    const sq_entry: [*]volatile u32 = @ptrFromInt(queue.sq.alias + queue.sq_tail * SQ_ENTRY_BYTES);
    for (0..command.len) |index| sq_entry[index] = command[index];
    sq_entry[0] = (command[0] & 0x0000_FFFF) | (@as(u32, cid) << 16);
    publishSubmission();
    queue.sq_tail = (queue.sq_tail + 1) % queue.entries;
    self.writeReg32(sqDoorbell(self, queue.qid), queue.sq_tail);
}

fn faultProbeCommand(nsid: u32, guard_phys: u32) [16]u32 {
    var command = @as([16]u32, @splat(0));
    command[0] = ADMIN_OPC_IDENTIFY;
    command[1] = nsid;
    command[6] = guard_phys;
    command[10] = IDENTIFY_CNS_NAMESPACE;
    return command;
}

fn fillGuardPage(guard_alias: usize) void {
    const bytes: [*]u8 = @ptrFromInt(guard_alias);
    @memset(bytes[0..PAGE_SIZE], 0xA5);
}

fn guardPageIntact(guard_alias: usize) bool {
    const bytes: [*]const u8 = @ptrFromInt(guard_alias);
    return guardPatternIntact(bytes[0..PAGE_SIZE]);
}

fn guardPatternIntact(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0xA5) return false;
    return true;
}

/// Allocate the queue, bounce and PRP frames for `dev` and return its DMA
/// isolation domain. This runs inside the device-independent enforcement step
/// while bus mastering is revoked; attach later programs exactly these frames.
pub fn prepareDma(dev: pci.PCIDevice) Error!intel_vtd.DmaDomain {
    if (pci.busMasteringEnabled(dev)) return error.BusMasteringNotRevoked;
    if (dma_frames == null) {
        const dma_base = paging.allocIdentityDmaFrames(DMA_FRAME_COUNT) orelse return error.QueueAllocationFailed;
        const dma_alias = paging.directMapAddress(dma_base) orelse {
            paging.releaseIdentityDmaFrames(dma_base, DMA_FRAME_COUNT) catch {};
            return error.QueueAllocationFailed;
        };
        const frames = DmaFrames{ .base = .{ .physical = dma_base, .alias = dma_alias } };
        dma_windows = frames.windows();
        dma_frames = frames;
        dma_device_id = pci.stableDeviceId(dev);
    } else if (dma_device_id != pci.stableDeviceId(dev)) return error.DmaIsolationPlanInvalid;
    return .{ .device = dev, .windows = &dma_windows };
}

pub fn attachAsBackend(dev: pci.PCIDevice) !?intel_vtd.FaultRecord {
    const operation_identity = try beginOperation();
    defer operation_lease.release(operation_identity);
    try dma_enforcement.ensureEnforced();
    const frames = dma_frames orelse return error.QueueAllocationFailed;
    if (dma_device_id != pci.stableDeviceId(dev)) return error.DmaIsolationPlanInvalid;
    // Without a platform IOMMU (virtual machines only), storage alone attaches
    // unisolated. Otherwise this requester must already be enforced.
    const isolation_required = intel_vtd.dmaIsolationEnabled();
    if (isolation_required and !intel_vtd.requesterProtected(dev)) return error.DmaIsolationBypassed;
    const bar = pci.memoryBar0(dev) orelse return error.BarUnmappable;
    if (bar.width != .bits64) return error.BarUnmappable;
    const aperture = pci.admitMemoryBar0(dev, BAR_MAP_BYTES) catch |err| return switch (err) {
        error.BusMasteringNotRevoked => error.BusMasteringNotRevoked,
        else => error.BarUnmappable,
    };
    msix_entry_physical = if (pci.msixTable(dev) catch null) |table| msixEntryPhysical(table, aperture) else null;
    publishInterruptsActive(false);
    for (0..DMA_FRAME_COUNT) |index| zeroFrame(frames.frame(@intCast(index)).alias);

    var controller = try prepare(dev, aperture.address, frames);
    var bus_master_enabled = false;
    errdefer if (bus_master_enabled) {
        controller.writeReg32(REG_CC, controller.reg32(REG_CC) & ~CC_EN);
        pci.disableBusMastering(dev);
        _ = spinUntilReady(&controller, false);
    };
    bus_master_enabled = true;
    pci.enableMemoryBusMastering(dev) catch return error.BusMasterEnableFailed;
    try enable(&controller);

    var fault_proof: ?intel_vtd.FaultRecord = null;
    if (isolation_required) {
        const guard_phys = paging.allocIdentityDmaFrames(1) orelse return error.QueueAllocationFailed;
        var guard_releasable = false;
        defer if (guard_releasable) paging.releaseIdentityDmaFrames(guard_phys, 1) catch {};
        const guard = DmaAddress{
            .physical = guard_phys,
            .alias = paging.directMapAddress(guard_phys) orelse return error.QueueAllocationFailed,
        };
        fillGuardPage(guard.alias);
        issueFaultProbe(&controller, guard.physical);
        fault_proof = try intel_vtd.waitForBlockedWrite(dev, guard.physical);

        // Reuse the aperture admitted before bus mastering. BAR sizing writes
        // are forbidden while this requester owns live DMA commands.
        controller = try prepare(dev, aperture.address, frames);
        if (!guardPageIntact(guard.alias)) return error.DmaIsolationBypassed;
        guard_releasable = true;
        try enable(&controller);
    }

    try createIoQueues(&controller, frames);
    var slot: usize = 0;
    while (slot < IO_PIPELINE_DEPTH) : (slot += 1) {
        controller.io_prp_lists[slot] = frames.prpList(slot);
        bounce[slot] = frames.bounce(slot);
    }
    try identifyNamespace(&controller, bounce[0]);
    active_controller = controller;
    active_device = dev;
    active_present = true;
    return fault_proof;
}

pub fn backendRead(start_lba: u64, buffer: []u8) bool {
    const identity = operationIdentity() catch return false;
    var io = BackendOperation{ .kind = .read, .start_lba = start_lba, .read_buffer = buffer.ptr, .buffer_len = buffer.len };
    return operation_lease.execute(identity, &io);
}

fn pipelineRead(start_lba: u64, buffer_ptr: [*]u8, total_sectors: usize) Error!void {
    var io = TransferIo{ .start_lba = start_lba, .read_buffer = buffer_ptr };
    try nvme_pipeline.transfer(OutstandingCommand, &io, total_sectors, BOUNCE_SECTORS, SECTOR_BYTES);
}

pub fn backendWrite(start_lba: u64, buffer: []const u8) bool {
    const identity = operationIdentity() catch return false;
    var io = BackendOperation{ .kind = .write, .start_lba = start_lba, .write_buffer = buffer.ptr, .buffer_len = buffer.len };
    return operation_lease.execute(identity, &io);
}

fn pipelineWrite(start_lba: u64, buffer_ptr: [*]const u8, total_sectors: usize) Error!void {
    var io = TransferIo{ .start_lba = start_lba, .write_buffer = buffer_ptr };
    try nvme_pipeline.transfer(OutstandingCommand, &io, total_sectors, BOUNCE_SECTORS, SECTOR_BYTES);
}

const TransferError = Error;
const TransferIo = struct {
    pub const Error = TransferError;
    start_lba: u64,
    read_buffer: ?[*]u8 = null,
    write_buffer: ?[*]const u8 = null,

    pub fn cancelled(_: *@This()) bool {
        return if (cooperative.current()) |worker| worker.cancel_requested else false;
    }
    pub fn authorized(_: *@This()) bool {
        return runtimeIoPermitted();
    }
    pub fn submit(self: *@This(), slot: usize, offset: usize, sectors: usize) TransferError!OutstandingCommand {
        if (self.write_buffer) |source| {
            const bytes: [*]u8 = @ptrFromInt(bounce[slot].alias);
            @memcpy(bytes[0 .. sectors * SECTOR_BYTES], (source + offset * SECTOR_BYTES)[0 .. sectors * SECTOR_BYTES]);
        }
        return submitIoCommand(&active_controller, if (self.read_buffer != null) NVM_OPC_READ else NVM_OPC_WRITE, self.start_lba + @as(u64, @intCast(offset)), bounce[slot], active_controller.io_prp_lists[slot], @intCast(sectors));
    }
    pub fn wait(_: *@This(), outstanding: []const OutstandingCommand) TransferError!u16 {
        return waitForAnyCompletion(&active_controller, &active_controller.io, outstanding);
    }
    pub fn completed(self: *@This(), value: TransferSlots.Completed) void {
        if (self.read_buffer) |destination| {
            const source: [*]const u8 = @ptrFromInt(bounce[value.index].alias);
            @memcpy((destination + value.sector_offset * SECTOR_BYTES)[0..value.byte_count], source[0..value.byte_count]);
        }
    }
};

fn beginOperation() Error!usize {
    const identity = try operationIdentity();
    if (!operation_lease.acquire(identity)) return error.Busy;
    return identity;
}

fn operationIdentity() Error!usize {
    // Do not consult the interrupted Worker or yield from an IRQ/AP caller.
    if (interrupt_context.active()) return error.InterruptContext;
    if (!smp.isRuntimeOwner()) return error.WrongCpu;
    return if (cooperative.current()) |worker| @intFromPtr(worker) else 1;
}

fn validateBackendTransfer(start_lba: u64, buffer_len: usize) ?usize {
    if (!active_present or bounce[0].physical == 0 or bounce[0].alias == 0) return null;
    if (buffer_len == 0 or buffer_len % SECTOR_BYTES != 0) return null;
    const total_sectors = buffer_len / SECTOR_BYTES;
    if (start_lba > active_controller.namespace_sectors or
        active_controller.namespace_sectors - start_lba < @as(u64, @intCast(total_sectors)))
    {
        return null;
    }
    return total_sectors;
}

pub fn backendFlush() bool {
    const identity = operationIdentity() catch return false;
    var io = BackendOperation{ .kind = .flush };
    return operation_lease.execute(identity, &io);
}

const BackendOperation = struct {
    kind: enum { read, write, flush },
    start_lba: u64 = 0,
    read_buffer: ?[*]u8 = null,
    write_buffer: ?[*]const u8 = null,
    buffer_len: usize = 0,

    pub fn perform(self: *@This()) Error!void {
        if (!runtimeIoPermitted()) return error.AuthorityRevoked;
        if (cooperative.current()) |worker| if (worker.cancel_requested) return error.Cancelled;
        switch (self.kind) {
            .read => try pipelineRead(self.start_lba, self.read_buffer.?, validateBackendTransfer(self.start_lba, self.buffer_len) orelse return error.EmptyTransfer),
            .write => try pipelineWrite(self.start_lba, self.write_buffer.?, validateBackendTransfer(self.start_lba, self.buffer_len) orelse return error.EmptyTransfer),
            .flush => {
                try flush(&active_controller);
                if (cooperative.current()) |worker| if (worker.cancel_requested) return error.Cancelled;
                if (!runtimeIoPermitted()) return error.AuthorityRevoked;
            },
        }
    }
    pub fn contain(_: *@This(), err: anyerror) void {
        handleBackendError(err);
    }
};

fn handleBackendError(err: anyerror) void {
    if (!backendErrorRequiresContainment(err) or !active_present) return;
    active_present = false;
    bounce = @as([IO_PIPELINE_DEPTH]DmaAddress, @splat(.{}));
    publishInterruptsActive(false);
    active_controller.writeReg32(REG_CC, active_controller.reg32(REG_CC) & ~CC_EN);
    pci.disableBusMastering(active_device);
    device_isolation.revokeInterrupt(active_device);
    _ = spinUntilReady(&active_controller, false);
    console.print(if (err == error.DmaFault)
        "ZIGOS:NVME:HW:DMA_FAULT_CONTAINED\n"
    else
        "ZIGOS:NVME:HW:COMMAND_FAILURE_CONTAINED\n");
}

fn backendErrorRequiresContainment(err: anyerror) bool {
    return err == error.DmaFault or
        err == error.ControllerFatal or
        err == error.CommandTimeout or
        err == error.CommandFailed or
        err == error.CompletionOwnershipMismatch;
}

pub fn sectorCount() u64 {
    if (!active_present) return 0;
    return active_controller.namespace_sectors;
}

/// The windows VT-d enforces for the attached controller, so the device
/// broker publishes the same isolation domain.
pub fn dmaWindows() []const intel_vtd.DmaWindow {
    if (!active_present) return &.{};
    return &dma_windows;
}

pub fn probeAndReport(dev: pci.PCIDevice) !?intel_vtd.FaultRecord {
    const fault_proof = try attachAsBackend(dev);
    console.print("ZIGOS:NVME:HW:CAP=");
    numfmt.printHex(active_controller.capabilities());
    console.print(" VS=");
    numfmt.printHex(active_controller.version());
    console.print(" RDY=1\n");
    console.print("ZIGOS:NVME:HW:BRINGUP_OK\n");
    console.print("ZIGOS:NVME:HW:IOQ_OK\n");
    return fault_proof;
}
