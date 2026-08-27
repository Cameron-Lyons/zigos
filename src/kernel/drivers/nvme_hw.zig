const console = @import("../utils/console.zig");
const spin = @import("../utils/spin.zig");
const x86 = @import("../../arch/x86.zig");
const timer = @import("../timer/timer.zig");
const tsc_clock = @import("../timer/tsc_clock.zig");
const interrupt_context = @import("../interrupts/context.zig");
const x2apic = @import("../interrupts/x2apic.zig");
const mmio_windows = @import("../memory/mmio_windows.zig");
const paging = @import("../memory/paging64.zig");
const dmar = @import("../platform/dmar.zig");
const intel_vtd = @import("../platform/intel_vtd.zig");
const nvme_completion = @import("nvme_completion.zig");
const nvme_interrupt = @import("nvme_interrupt.zig");
const nvme_pipeline = @import("nvme_pipeline.zig");
const nvme_prp = @import("nvme_prp.zig");
const nvme_timing = @import("nvme_timing.zig");
const pci = @import("pci.zig");

pub const SECTOR_BYTES: usize = 512;
pub const INTERRUPT_VECTOR = nvme_interrupt.INTERRUPT_VECTOR;
pub const INTERRUPT_STATE_USES_PROTOCOL_ORDERING = true;
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

comptime {
    if (@as(usize, BAR_MAP_BYTES) > mmio_windows.nvme.bytes) {
        @compileError("NVMe BAR mapping exceeds its reserved MMIO window");
    }
}

pub const Error = error{
    BarUnmappable,
    ControllerResetTimeout,
    ControllerEnableTimeout,
    ControllerFatal,
    QueueAllocationFailed,
    BusMasteringNotRevoked,
    CommandTimeout,
    CommandFailed,
    CompletionOwnershipMismatch,
    TransferTooLarge,
    EmptyTransfer,
    LbaOutOfRange,
    NamespaceMissing,
    UnsupportedLbaFormat,
    DmaIsolationBypassed,
    TooManyDmaDomains,
    DmaFault,
    InterruptIsolationUnavailable,
    InterruptRouteInstallFailed,
    MsiEnableFailed,
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
const MAX_ADDITIONAL_DMA_DOMAINS: usize = 2;

const Queue = struct {
    sq_phys: u32,
    cq_phys: u32,
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
    base: u32,

    fn frame(self: DmaFrames, index: u32) u32 {
        return self.base + index * PAGE_SIZE;
    }

    fn windows(self: DmaFrames) [DMA_WINDOW_COUNT]intel_vtd.DmaWindow {
        return .{
            .{ .base = self.frame(0), .device_readable = true, .device_writable = false },
            .{ .base = self.frame(1), .device_readable = false, .device_writable = true },
            .{ .base = self.frame(2), .device_readable = true, .device_writable = false },
            .{ .base = self.frame(3), .device_readable = false, .device_writable = true },
            .{
                .base = self.frame(BOUNCE_FIRST_FRAME),
                .length = @intCast(nvme_prp.MAX_TRANSFER_BYTES * IO_PIPELINE_DEPTH),
                .device_readable = true,
                .device_writable = true,
            },
            .{
                .base = self.frame(PRP_LIST_FIRST_FRAME),
                .length = PAGE_SIZE * PRP_LIST_PAGE_COUNT,
                .device_readable = true,
                .device_writable = false,
            },
        };
    }

    fn bounce(self: DmaFrames, slot: usize) u32 {
        return self.frame(BOUNCE_FIRST_FRAME + @as(u32, @intCast(slot)) * BOUNCE_SLOT_PAGE_COUNT);
    }

    fn prpList(self: DmaFrames, slot: usize) u32 {
        return self.frame(PRP_LIST_FIRST_FRAME + @as(u32, @intCast(slot)));
    }
};

pub const Controller = struct {
    bar: usize,
    doorbell_stride: usize,
    admin: Queue,
    io: Queue = undefined,
    io_ready: bool = false,
    nsid: u32 = 1,
    lba_bytes: u32 = SECTOR_BYTES,
    namespace_sectors: u64 = 0,
    io_prp_list_phys: [IO_PIPELINE_DEPTH]u32 = [_]u32{0} ** IO_PIPELINE_DEPTH,

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

fn barPhysicalAddress(dev: pci.PCIDevice) ?usize {
    const bar = pci.memoryBar0(dev) orelse return null;
    if (bar.width != .bits64) return null;
    return bar.address;
}

fn mapBar(phys: usize) usize {
    var offset: u32 = 0;
    while (offset < BAR_MAP_BYTES) : (offset += PAGE_SIZE) {
        const page_offset: usize = offset;
        paging.mapKernelBorrowedPage(
            mmio_windows.nvme.base + page_offset,
            phys + page_offset,
            paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE,
        );
    }
    return mmio_windows.nvme.base;
}

fn doorbellStride(cap: u64) usize {
    const dstrd: u5 = @intCast((cap >> 32) & 0xF);
    return @as(usize, 4) << dstrd;
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

fn prepare(dev: pci.PCIDevice, frames: DmaFrames) Error!Controller {
    const bar_phys = barPhysicalAddress(dev) orelse return error.BarUnmappable;
    if (bar_phys == 0) return error.BarUnmappable;

    const bar = mapBar(bar_phys);

    var controller = Controller{
        .bar = bar,
        .doorbell_stride = doorbellStride((@as(u64, @as(*volatile u32, @ptrFromInt(bar + REG_CAP + 4)).*) << 32) |
            @as(u64, @as(*volatile u32, @ptrFromInt(bar + REG_CAP)).*)),
        .admin = undefined,
    };

    controller.writeReg32(REG_CC, controller.reg32(REG_CC) & ~CC_EN);
    if (!spinUntilReady(&controller, false)) {
        if (controller.fatal()) return error.ControllerFatal;
        return error.ControllerResetTimeout;
    }

    const sq_phys = frames.frame(0);
    const cq_phys = frames.frame(1);
    zeroFrame(sq_phys);
    zeroFrame(cq_phys);
    controller.admin = .{ .sq_phys = sq_phys, .cq_phys = cq_phys, .entries = ADMIN_QUEUE_ENTRIES, .qid = 0 };

    const aqa = ((ADMIN_QUEUE_ENTRIES - 1) << 16) | (ADMIN_QUEUE_ENTRIES - 1);
    controller.writeReg32(REG_AQA, aqa);
    controller.writeReg64(REG_ASQ, sq_phys);
    controller.writeReg64(REG_ACQ, cq_phys);

    return controller;
}

fn enable(self: *Controller) Error!void {
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

    const sq_entry: [*]volatile u32 = @ptrFromInt(queue.sq_phys + queue.sq_tail * SQ_ENTRY_BYTES);
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
    if (outstanding.len == 0) return error.CompletionOwnershipMismatch;
    const cqe: [*]volatile u32 = @ptrFromInt(queue.cq_phys + queue.cq_head * CQ_ENTRY_BYTES);
    const wait_with_interrupt = nvme_interrupt.mayIdleWait(
        queue.qid,
        interruptsActive(),
        interrupt_context.active(),
    );
    const restore_interrupt_mask = wait_with_interrupt and !x86.interruptsEnabled();
    var spins: u64 = 0;
    while (true) : (spins +%= 1) {
        if (wait_with_interrupt or (spins & 0x3FF) == 0) {
            for (outstanding) |command| {
                if (command.deadline.expired()) return error.CommandTimeout;
            }
            if (self.fatal()) return error.ControllerFatal;
            if (intel_vtd.faultMonitoringEnabled() and
                (intel_vtd.pollFault() catch return error.DmaFault) != null)
            {
                return error.DmaFault;
            }
        }
        const status_dword = cqe[3];
        if (nvme_completion.phase(status_dword) == queue.phase) {
            acquireCompletion();
            const completion = nvme_completion.decode(cqe[2], cqe[3]);
            if (!completion.belongsToQueue(queue.qid, queue.entries) or
                !containsCommandId(outstanding, completion.command_id))
            {
                return error.CompletionOwnershipMismatch;
            }
            queue.cq_head = (queue.cq_head + 1) % queue.entries;
            if (queue.cq_head == 0) queue.phase ^= 1;
            self.writeReg32(cqDoorbell(self, queue.qid), queue.cq_head);
            if (intel_vtd.faultMonitoringEnabled() and
                (intel_vtd.pollFault() catch return error.DmaFault) != null)
            {
                return error.DmaFault;
            }
            if (!completion.succeeded()) return error.CommandFailed;
            return completion.command_id;
        }
        if (wait_with_interrupt) {
            timer.armSchedulerTick();
            x86.cli();
            if (nvme_completion.phase(cqe[3]) == queue.phase) {
                if (!restore_interrupt_mask) x86.sti();
                continue;
            }
            x86.stiHlt();
            if (restore_interrupt_mask) x86.cli();
        } else {
            spin.hint();
        }
    }
}

fn containsCommandId(outstanding: []const OutstandingCommand, cid: u16) bool {
    for (outstanding) |command| {
        if (command.cid == cid) return true;
    }
    return false;
}

fn submit(self: *Controller, queue: *Queue, command: *const [16]u32) Error!void {
    const outstanding = [_]OutstandingCommand{submitCommand(self, queue, command)};
    _ = try waitForAnyCompletion(self, queue, &outstanding);
}

pub fn createIoQueues(self: *Controller, frames: DmaFrames) Error!void {
    const cq_phys = frames.frame(3);
    const sq_phys = frames.frame(2);
    zeroFrame(cq_phys);
    zeroFrame(sq_phys);

    var create_cq = [_]u32{0} ** 16;
    create_cq[0] = ADMIN_OPC_CREATE_IO_CQ;
    create_cq[6] = cq_phys;
    create_cq[10] = ((IO_QUEUE_ENTRIES - 1) << 16) | IO_QUEUE_ID;
    create_cq[11] = nvme_interrupt.createCompletionQueueControl();
    try submit(self, &self.admin, &create_cq);

    var create_sq = [_]u32{0} ** 16;
    create_sq[0] = ADMIN_OPC_CREATE_IO_SQ;
    create_sq[6] = sq_phys;
    create_sq[10] = ((IO_QUEUE_ENTRIES - 1) << 16) | IO_QUEUE_ID;
    create_sq[11] = (@as(u32, IO_QUEUE_ID) << 16) | 1;
    try submit(self, &self.admin, &create_sq);

    self.io = .{ .sq_phys = sq_phys, .cq_phys = cq_phys, .entries = IO_QUEUE_ENTRIES, .qid = IO_QUEUE_ID };
    self.io_ready = true;
}

fn submitIoCommand(
    self: *Controller,
    opcode: u32,
    lba: u64,
    buffer_phys: u32,
    prp_list_phys: u32,
    sector_count: u16,
) Error!OutstandingCommand {
    if (!self.io_ready) return error.NamespaceMissing;

    if (sector_count == 0) return error.EmptyTransfer;
    const transfer_bytes = @as(usize, sector_count) * self.lba_bytes;
    const prp = nvme_prp.plan(buffer_phys, prp_list_phys, transfer_bytes) catch |err| switch (err) {
        error.EmptyTransfer => return error.EmptyTransfer,
        error.TransferTooLarge => return error.TransferTooLarge,
        else => return error.DmaIsolationBypassed,
    };
    const prp_list: [*]volatile u64 = @ptrFromInt(prp_list_phys);
    for (0..prp.list_entry_count) |index| {
        prp_list[index] = prp.listEntryAddress(index) orelse return error.DmaIsolationBypassed;
    }

    if (lba > self.namespace_sectors or self.namespace_sectors - lba < sector_count) return error.LbaOutOfRange;
    var cmd = [_]u32{0} ** 16;
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

pub fn readSectors(self: *Controller, lba: u64, buffer_phys: u32, sector_count: u16) Error!void {
    const command = try submitIoCommand(
        self,
        NVM_OPC_READ,
        lba,
        buffer_phys,
        self.io_prp_list_phys[0],
        sector_count,
    );
    try waitForIoCommand(self, command);
}

pub fn writeSectors(self: *Controller, lba: u64, buffer_phys: u32, sector_count: u16) Error!void {
    const command = try submitIoCommand(
        self,
        NVM_OPC_WRITE,
        lba,
        buffer_phys,
        self.io_prp_list_phys[0],
        sector_count,
    );
    try waitForIoCommand(self, command);
}

pub fn flush(self: *Controller) Error!void {
    if (!self.io_ready) return error.NamespaceMissing;
    var command = [_]u32{0} ** 16;
    command[0] = NVM_OPC_FLUSH;
    command[1] = self.nsid;
    try submit(self, &self.io, &command);
}

fn zeroFrame(phys: u32) void {
    const bytes: [*]u8 = @ptrFromInt(phys);
    @memset(bytes[0..PAGE_SIZE], 0);
}

fn publishSubmission() void {
    asm volatile ("mfence" ::: .{ .memory = true });
}

fn acquireCompletion() void {
    asm volatile ("lfence" ::: .{ .memory = true });
}

var active_controller: Controller = undefined;
var active_device: pci.PCIDevice = undefined;
var active_present: bool = false;
var bounce_phys: [IO_PIPELINE_DEPTH]u32 = [_]u32{0} ** IO_PIPELINE_DEPTH;
var io_interrupts_active: bool = false;
var completion_interrupt_count: u64 = 0;

fn interruptsActive() bool {
    return @atomicLoad(bool, &io_interrupts_active, .acquire);
}

fn publishInterruptsActive(value: bool) void {
    @atomicStore(bool, &io_interrupts_active, value, .release);
}

fn resetCompletionInterruptCount() void {
    @atomicStore(u64, &completion_interrupt_count, 0, .monotonic);
}

pub fn attached() bool {
    return active_present;
}

pub fn activateInterrupts() Error!void {
    if (!active_present) return error.NamespaceMissing;
    if (interruptsActive()) return;
    if (!intel_vtd.interruptIsolationEnabled()) return error.InterruptIsolationUnavailable;
    const remapped = intel_vtd.routeInterrupt(
        active_device,
        INTERRUPT_VECTOR,
        x2apic.localId(),
    ) catch return error.InterruptRouteInstallFailed;
    pci.enableSingleMsi(active_device, .{
        .address = remapped.address,
        .data = remapped.data,
    }) catch return error.MsiEnableFailed;
    resetCompletionInterruptCount();
    publishInterruptsActive(true);
}

pub fn handleInterrupt() void {
    if (interruptsActive()) {
        _ = @atomicRmw(u64, &completion_interrupt_count, .Add, 1, .monotonic);
    }
    x2apic.acknowledge();
}

pub fn completionInterruptCount() u64 {
    return @atomicLoad(u64, &completion_interrupt_count, .monotonic);
}

fn identifyNamespace(self: *Controller, buffer: u32) Error!void {
    zeroFrame(buffer);
    var cmd = [_]u32{0} ** 16;
    cmd[0] = ADMIN_OPC_IDENTIFY;
    cmd[1] = self.nsid;
    cmd[6] = buffer;
    cmd[10] = IDENTIFY_CNS_NAMESPACE;
    try submit(self, &self.admin, &cmd);
    const words: [*]volatile u32 = @ptrFromInt(buffer);
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

    const sq_entry: [*]volatile u32 = @ptrFromInt(queue.sq_phys + queue.sq_tail * SQ_ENTRY_BYTES);
    for (0..command.len) |index| sq_entry[index] = command[index];
    sq_entry[0] = (command[0] & 0x0000_FFFF) | (@as(u32, cid) << 16);
    publishSubmission();
    queue.sq_tail = (queue.sq_tail + 1) % queue.entries;
    self.writeReg32(sqDoorbell(self, queue.qid), queue.sq_tail);
}

fn faultProbeCommand(nsid: u32, guard_phys: u32) [16]u32 {
    var command = [_]u32{0} ** 16;
    command[0] = ADMIN_OPC_IDENTIFY;
    command[1] = nsid;
    command[6] = guard_phys;
    command[10] = IDENTIFY_CNS_NAMESPACE;
    return command;
}

fn fillGuardPage(guard_phys: u32) void {
    const bytes: [*]u8 = @ptrFromInt(guard_phys);
    @memset(bytes[0..PAGE_SIZE], 0xA5);
}

fn guardPageIntact(guard_phys: u32) bool {
    const bytes: [*]const u8 = @ptrFromInt(guard_phys);
    return guardPatternIntact(bytes[0..PAGE_SIZE]);
}

fn guardPatternIntact(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0xA5) return false;
    return true;
}

pub fn attachAsBackend(
    dev: pci.PCIDevice,
    vtd_summary: ?*const dmar.Summary,
    additional_domains: []const intel_vtd.DmaDomain,
) !?intel_vtd.FaultRecord {
    if (pci.busMasteringEnabled(dev)) return error.BusMasteringNotRevoked;
    if (additional_domains.len > MAX_ADDITIONAL_DMA_DOMAINS) {
        return error.TooManyDmaDomains;
    }
    publishInterruptsActive(false);
    resetCompletionInterruptCount();
    const dma_base = paging.allocLowIdentityFrames(DMA_FRAME_COUNT) orelse return error.QueueAllocationFailed;
    const frames = DmaFrames{ .base = dma_base };
    var retain_dma_frames = vtd_summary != null;
    errdefer if (!retain_dma_frames) paging.releaseLowIdentityFrames(dma_base, DMA_FRAME_COUNT) catch {};
    for (0..DMA_FRAME_COUNT) |index| zeroFrame(frames.frame(@intCast(index)));

    var controller = try prepare(dev, frames);
    var bus_master_enabled = false;
    errdefer if (bus_master_enabled) {
        controller.writeReg32(REG_CC, controller.reg32(REG_CC) & ~CC_EN);
        pci.disableBusMastering(dev);
        _ = spinUntilReady(&controller, false);
    };
    const windows = frames.windows();
    if (vtd_summary) |summary| {
        var domains: [1 + MAX_ADDITIONAL_DMA_DOMAINS]intel_vtd.DmaDomain = undefined;
        domains[0] = .{ .device = dev, .windows = &windows };
        var domain_count: usize = 1;
        for (additional_domains) |domain| {
            domains[domain_count] = domain;
            domain_count += 1;
        }
        try intel_vtd.enforceDevices(summary, domains[0..domain_count]);
    }
    pci.enableMemoryBusMastering(dev);
    bus_master_enabled = true;
    try enable(&controller);

    var fault_proof: ?intel_vtd.FaultRecord = null;
    if (vtd_summary != null) {
        const guard_phys = paging.allocLowIdentityFrames(1) orelse return error.QueueAllocationFailed;
        var guard_releasable = false;
        defer if (guard_releasable) paging.releaseLowIdentityFrames(guard_phys, 1) catch {};
        fillGuardPage(guard_phys);
        issueFaultProbe(&controller, guard_phys);
        fault_proof = try intel_vtd.waitForBlockedWrite(guard_phys);

        controller = try prepare(dev, frames);
        if (!guardPageIntact(guard_phys)) return error.DmaIsolationBypassed;
        guard_releasable = true;
        try enable(&controller);
    }

    try createIoQueues(&controller, frames);
    var slot: usize = 0;
    while (slot < IO_PIPELINE_DEPTH) : (slot += 1) {
        controller.io_prp_list_phys[slot] = frames.prpList(slot);
        bounce_phys[slot] = frames.bounce(slot);
    }
    try identifyNamespace(&controller, bounce_phys[0]);
    active_controller = controller;
    active_device = dev;
    active_present = true;
    retain_dma_frames = true;
    return fault_proof;
}

pub fn backendRead(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
    const total_sectors = validateBackendTransfer(start_lba, buffer_len) orelse return false;
    pipelineRead(start_lba, buffer_ptr, total_sectors) catch |err| {
        handleBackendError(err);
        return false;
    };
    return true;
}

fn pipelineRead(start_lba: u64, buffer_ptr: [*]u8, total_sectors: usize) Error!void {
    var slots = TransferSlots{};
    var next_sector: usize = 0;
    while (next_sector < total_sectors or slots.active_count != 0) {
        while (next_sector < total_sectors and slots.active_count < IO_PIPELINE_DEPTH) {
            const slot_index = slots.freeIndex() orelse unreachable;
            const chunk = @min(total_sectors - next_sector, BOUNCE_SECTORS);
            const command = try submitIoCommand(
                &active_controller,
                NVM_OPC_READ,
                start_lba + @as(u64, @intCast(next_sector)),
                bounce_phys[slot_index],
                active_controller.io_prp_list_phys[slot_index],
                @intCast(chunk),
            );
            if (!slots.activate(
                slot_index,
                command,
                next_sector,
                chunk * SECTOR_BYTES,
            )) unreachable;
            next_sector += chunk;
        }

        var outstanding_buffer: [IO_PIPELINE_DEPTH]OutstandingCommand = undefined;
        const outstanding = slots.collect(&outstanding_buffer);
        const completed_cid = try waitForAnyCompletion(&active_controller, &active_controller.io, outstanding);
        const completed = slots.complete(completed_cid) orelse
            return error.CompletionOwnershipMismatch;
        const bounce: [*]const u8 = @ptrFromInt(bounce_phys[completed.index]);
        @memcpy(
            (buffer_ptr + completed.sector_offset * SECTOR_BYTES)[0..completed.byte_count],
            bounce[0..completed.byte_count],
        );
    }
}

pub fn backendWrite(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
    const total_sectors = validateBackendTransfer(start_lba, buffer_len) orelse return false;
    pipelineWrite(start_lba, buffer_ptr, total_sectors) catch |err| {
        handleBackendError(err);
        return false;
    };
    return true;
}

fn pipelineWrite(start_lba: u64, buffer_ptr: [*]const u8, total_sectors: usize) Error!void {
    var slots = TransferSlots{};
    var next_sector: usize = 0;
    while (next_sector < total_sectors or slots.active_count != 0) {
        while (next_sector < total_sectors and slots.active_count < IO_PIPELINE_DEPTH) {
            const slot_index = slots.freeIndex() orelse unreachable;
            const chunk = @min(total_sectors - next_sector, BOUNCE_SECTORS);
            const chunk_bytes = chunk * SECTOR_BYTES;
            const bounce: [*]u8 = @ptrFromInt(bounce_phys[slot_index]);
            @memcpy(
                bounce[0..chunk_bytes],
                (buffer_ptr + next_sector * SECTOR_BYTES)[0..chunk_bytes],
            );
            const command = try submitIoCommand(
                &active_controller,
                NVM_OPC_WRITE,
                start_lba + @as(u64, @intCast(next_sector)),
                bounce_phys[slot_index],
                active_controller.io_prp_list_phys[slot_index],
                @intCast(chunk),
            );
            if (!slots.activate(slot_index, command, next_sector, chunk_bytes)) unreachable;
            next_sector += chunk;
        }

        var outstanding_buffer: [IO_PIPELINE_DEPTH]OutstandingCommand = undefined;
        const outstanding = slots.collect(&outstanding_buffer);
        const completed_cid = try waitForAnyCompletion(&active_controller, &active_controller.io, outstanding);
        _ = slots.complete(completed_cid) orelse return error.CompletionOwnershipMismatch;
    }
}

fn validateBackendTransfer(start_lba: u64, buffer_len: usize) ?usize {
    if (!active_present or bounce_phys[0] == 0) return null;
    if (buffer_len == 0 or buffer_len % SECTOR_BYTES != 0) return null;
    const total_sectors = buffer_len / SECTOR_BYTES;
    if (start_lba > active_controller.namespace_sectors or
        active_controller.namespace_sectors - start_lba < @as(u64, @intCast(total_sectors)))
    {
        return null;
    }
    return total_sectors;
}

pub fn backendFlush() callconv(.c) bool {
    if (!active_present) return false;
    flush(&active_controller) catch |err| {
        handleBackendError(err);
        return false;
    };
    return true;
}

fn handleBackendError(err: anyerror) void {
    if (!backendErrorRequiresContainment(err) or !active_present) return;
    active_present = false;
    bounce_phys = [_]u32{0} ** IO_PIPELINE_DEPTH;
    publishInterruptsActive(false);
    pci.disableMsi(active_device) catch {};
    active_controller.writeReg32(REG_CC, active_controller.reg32(REG_CC) & ~CC_EN);
    pci.disableBusMastering(active_device);
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

export fn zigosStorageBootstrapNvmeAttached() callconv(.c) bool {
    return active_present;
}

export fn zigosStorageBootstrapNvmeSectorCount() callconv(.c) u64 {
    if (!active_present) return 0;
    return active_controller.namespace_sectors;
}

export fn zigosStorageBootstrapNvmeRead(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
    return backendRead(start_lba, buffer_ptr, buffer_len);
}

export fn zigosStorageBootstrapNvmeWrite(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
    return backendWrite(start_lba, buffer_ptr, buffer_len);
}

export fn zigosStorageBootstrapNvmeFlush() callconv(.c) bool {
    return backendFlush();
}

export fn zigosStorageBootstrapNvmeDmaWindow(
    index: u32,
    base_out: *u64,
    length_out: *u64,
    device_readable_out: *bool,
    device_writable_out: *bool,
) callconv(.c) bool {
    if (!active_present) return false;
    const Window = struct { phys: u32, length: u64 = PAGE_SIZE, readable: bool, writable: bool };
    const window: Window = switch (index) {
        0 => .{ .phys = active_controller.admin.sq_phys, .readable = true, .writable = false },
        1 => .{ .phys = active_controller.admin.cq_phys, .readable = false, .writable = true },
        2 => .{ .phys = active_controller.io.sq_phys, .readable = true, .writable = false },
        3 => .{ .phys = active_controller.io.cq_phys, .readable = false, .writable = true },
        4 => .{
            .phys = bounce_phys[0],
            .length = nvme_prp.MAX_TRANSFER_BYTES * IO_PIPELINE_DEPTH,
            .readable = true,
            .writable = true,
        },
        5 => .{
            .phys = active_controller.io_prp_list_phys[0],
            .length = PAGE_SIZE * IO_PIPELINE_DEPTH,
            .readable = true,
            .writable = false,
        },
        else => return false,
    };
    base_out.* = window.phys;
    length_out.* = window.length;
    device_readable_out.* = window.readable;
    device_writable_out.* = window.writable;
    return true;
}

pub fn probeAndReport(
    dev: pci.PCIDevice,
    vtd_summary: ?*const dmar.Summary,
    additional_domains: []const intel_vtd.DmaDomain,
) !?intel_vtd.FaultRecord {
    const fault_proof = try attachAsBackend(dev, vtd_summary, additional_domains);
    console.print("ZIGOS:NVME:HW:CAP=");
    printHex64(active_controller.capabilities());
    console.print(" VS=");
    printHex32(active_controller.version());
    console.print(" RDY=1\n");
    console.print("ZIGOS:NVME:HW:BRINGUP_OK\n");
    console.print("ZIGOS:NVME:HW:IOQ_OK\n");
    return fault_proof;
}

comptime {
    _ = &roundtripSelfTest;
}

const SCRATCH_LBA: u64 = 8;
const TEST_PATTERN: u8 = 0xA5;

fn roundtripSelfTest(dev: pci.PCIDevice) void {
    _ = attachAsBackend(dev, null, &.{}) catch |err| {
        console.print("ZIGOS:NVME:HW:IOQ_FAIL ");
        console.print(@errorName(err));
        console.print("\n");
        return;
    };
    console.print("ZIGOS:NVME:HW:IOQ_OK\n");

    const scratch_phys = paging.allocLowIdentityFrames(1) orelse {
        console.print("ZIGOS:NVME:HW:RW_FAIL QueueAllocationFailed\n");
        return;
    };
    const bytes: [*]u8 = @ptrFromInt(scratch_phys);

    var i: usize = 0;
    while (i < SECTOR_BYTES) : (i += 1) bytes[i] = TEST_PATTERN;
    if (!backendWrite(SCRATCH_LBA, bytes, SECTOR_BYTES)) {
        console.print("ZIGOS:NVME:HW:RW_FAIL write\n");
        return;
    }

    i = 0;
    while (i < SECTOR_BYTES) : (i += 1) bytes[i] = 0;
    if (!backendRead(SCRATCH_LBA, bytes, SECTOR_BYTES)) {
        console.print("ZIGOS:NVME:HW:RW_FAIL read\n");
        return;
    }

    i = 0;
    while (i < SECTOR_BYTES) : (i += 1) {
        if (bytes[i] != TEST_PATTERN) {
            console.print("ZIGOS:NVME:HW:RW_FAIL verify\n");
            return;
        }
    }
    console.print("ZIGOS:NVME:HW:RW_ROUNDTRIP_OK\n");
}

const hex_digits = "0123456789abcdef";

fn printHex32(value: u32) void {
    var buffer: [8]u8 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u5 = @intCast((7 - i) * 4);
        buffer[i] = hex_digits[(value >> shift) & 0xF];
    }
    console.print(buffer[0..]);
}

fn printHex64(value: u64) void {
    var buffer: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const shift: u6 = @intCast((15 - i) * 4);
        buffer[i] = hex_digits[@as(usize, @intCast((value >> shift) & 0xF))];
    }
    console.print(buffer[0..]);
}
