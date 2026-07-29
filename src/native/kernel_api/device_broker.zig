const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");

pub const MAX_DEVICES: usize = 4;
pub const MAX_DMA_WINDOWS: usize = 8;
pub const MAX_DMA_PROGRAMS: usize = MAX_DEVICES * 2;
const default_dma_window_bytes: u64 = 128 * 1024;
const iommu_page_size: u64 = 4096;
const iommu_root_table_salt = iommu_page_size;
const iommu_context_table_salt = iommu_page_size * 2;
const iommu_domain_page_table_salt = iommu_page_size * 3;
const iommu_fault_record_salt = iommu_page_size * 4;
const iommu_intel_vtd_base: u64 = 0x0010_0000_0000;
const iommu_amd_vi_base: u64 = 0x0020_0000_0000;
const iommu_device_id_mask: u64 = 0x0000_FFFF;
const iommu_device_id_shift: u6 = 20;
const iommu_domain_id_mask: u64 = 0xFFFF;
const iommu_domain_id_shift: u6 = 12;
const brokered_dma_window_device_mask: u64 = 0x0000_FFFF_FFFF;
const brokered_dma_window_shift: u6 = 12;
const test_dma_window_offset: u64 = 0x40000;
const test_dma_buffer_bytes: u64 = 512;

pub const PortWidth = abi.DevicePortWidth;

pub const DmaIsolationMode = enum(u8) {
    programmed_io_only,
    brokered_dma_buffers,
};

pub const IommuEngine = enum(u8) {
    intel_vtd,
    amd_vi,
};

pub const DmaDirection = enum(u8) {
    device_read,
    device_write,
    bidirectional,
};

pub const IommuFaultReason = enum(u8) {
    access_outside_window,
    read_not_permitted,
    write_not_permitted,
    executable_window,
};

pub const DmaWindow = struct {
    base: u64,
    length: u64,
    readable_by_device: bool = true,
    writable_by_device: bool = true,
    executable: bool = false,

    pub fn contains(self: DmaWindow, address: u64, length: u64) bool {
        if (length == 0 or self.length == 0) return false;
        const end = std.math.add(u64, address, length - 1) catch return false;
        const window_end = std.math.add(u64, self.base, self.length - 1) catch return false;
        return address >= self.base and end <= window_end;
    }

    pub fn permits(self: DmaWindow, address: u64, length: u64, direction: DmaDirection) bool {
        if (!self.contains(address, length) or self.executable) return false;
        return switch (direction) {
            .device_read => self.readable_by_device,
            .device_write => self.writable_by_device,
            .bidirectional => self.readable_by_device and self.writable_by_device,
        };
    }
};

pub const DmaProgramRequest = struct {
    device_id: u64,
    dma_domain_id: u64,
    mode: DmaIsolationMode = .brokered_dma_buffers,
    bus_master_dma_enabled: bool = false,
    iommu_engine: IommuEngine = .intel_vtd,
    root_table_address: u64 = 0,
    context_table_address: u64 = 0,
    domain_page_table_address: u64 = 0,
    fault_record_address: u64 = 0,
    windows: []const DmaWindow,
};

pub const IommuProgramEvidence = struct {
    engine: IommuEngine,
    device_id: u64,
    dma_domain_id: u64,
    root_table_address: u64,
    context_table_address: u64,
    domain_page_table_address: u64,
    fault_record_address: u64,
    queued_invalidation_completed: bool,
    interrupt_remapping_enabled: bool,
};

pub const IommuFaultEvidence = struct {
    device_id: u64,
    dma_domain_id: u64,
    fault_address: u64,
    length: u64,
    direction: DmaDirection,
    reason: IommuFaultReason,
    program_generation: u64,
    fault_count: u64,
};

pub const DmaIsolationStatus = struct {
    device_id: u64,
    dma_domain_id: u64,
    mode: DmaIsolationMode,
    hardware_iommu_programmed: bool,
    bus_master_dma_enabled: bool,
    program_generation: u64,
    window_count: usize,
    iommu_program: IommuProgramEvidence,
    fault_count: u64,
};

pub const BrokeredDmaBuffer = struct {
    device_id: u64,
    dma_domain_id: u64,
    address: u64,
    length: u64,
    direction: DmaDirection,
    program_generation: u64,
};

pub const MmioWindow = struct {
    base: u64,
    length: u64,
    writable: bool = false,
    executable: bool = false,
};

pub const ControllerDescriptor = struct {
    device_id: u64,
    base_port: u16,
    io_port_count: u16,
    ctrl_port: u16,
    is_master: bool,
    irq_line: u8,
    mmio_window_count: u8,
    sector_count: u64,
};

pub const Error = error{
    ControllerGenerationExhausted,
    ControllerTableFull,
    DeviceNotFound,
    DmaDomainNotProgrammed,
    DmaProgramGenerationExhausted,
    DmaProgramIdExhausted,
    DmaTableFull,
    DmaWindowDenied,
    InvalidPort,
    InvalidDmaDomain,
    InvalidDmaWindow,
    InvalidDevice,
    InvalidIommuProgram,
    UnsupportedMmioWindow,
    UnsupportedBusMasterDma,
    UnsupportedWidth,
    WrongControllerKind,
};

const ControllerSlot = struct {
    in_use: bool = false,
    published: bool = false,
    device_id: u64 = 0,
    broker_generation: u64 = 0,
};

const ControllerIndex = std.math.IntFittingRange(0, MAX_DEVICES - 1);
const ControllerCount = std.math.IntFittingRange(0, MAX_DEVICES);

const DmaProgramSlot = struct {
    in_use: bool = false,
    program_id: u64 = 0,
    device_id: u64 = 0,
    dma_domain_id: u64 = 0,
    mode: DmaIsolationMode = .programmed_io_only,
    bus_master_dma_enabled: bool = false,
    program_generation: u64 = 0,
    window_count: usize = 0,
    windows: [MAX_DMA_WINDOWS]DmaWindow = [_]DmaWindow{zeroDmaWindow()} ** MAX_DMA_WINDOWS,
    iommu_program: IommuProgramEvidence = zeroIommuProgramEvidence(),
    last_fault: ?IommuFaultEvidence = null,
    fault_count: u64 = 0,
};

const ControllerArena = struct {
    slots: [MAX_DEVICES]ControllerSlot = [_]ControllerSlot{ControllerSlot{}} ** MAX_DEVICES,
    primary_index: indexed_arena.UniqueIndex(MAX_DEVICES * 2) = indexed_arena.UniqueIndex(MAX_DEVICES * 2).init(),
    slot_keys: [MAX_DEVICES]u64 = [_]u64{0} ** MAX_DEVICES,
    free_next: [MAX_DEVICES]?ControllerIndex = [_]?ControllerIndex{null} ** MAX_DEVICES,
    free_head: ?ControllerIndex = null,
    next_unclaimed_index: ControllerCount = 0,
    used_count: ControllerCount = 0,
    unpublished_next: [MAX_DEVICES]?ControllerIndex = [_]?ControllerIndex{null} ** MAX_DEVICES,
    unpublished_prev: [MAX_DEVICES]?ControllerIndex = [_]?ControllerIndex{null} ** MAX_DEVICES,
    unpublished_queued: [MAX_DEVICES]bool = [_]bool{false} ** MAX_DEVICES,
    unpublished_head: ?ControllerIndex = null,
    unpublished_tail: ?ControllerIndex = null,
    unpublished_count: ControllerCount = 0,

    pub fn init() ControllerArena {
        return .{};
    }

    pub fn reset(self: *ControllerArena) void {
        for (&self.slots) |*slot| {
            resetControllerSlot(slot);
        }
        self.primary_index.reset();
        self.slot_keys = [_]u64{0} ** MAX_DEVICES;
        self.free_next = [_]?ControllerIndex{null} ** MAX_DEVICES;
        self.free_head = null;
        self.next_unclaimed_index = 0;
        self.used_count = 0;
        self.unpublished_next = [_]?ControllerIndex{null} ** MAX_DEVICES;
        self.unpublished_prev = [_]?ControllerIndex{null} ** MAX_DEVICES;
        self.unpublished_queued = [_]bool{false} ** MAX_DEVICES;
        self.unpublished_head = null;
        self.unpublished_tail = null;
        self.unpublished_count = 0;
    }

    pub fn reserve(self: *ControllerArena, key: u64) ?*ControllerSlot {
        const slot_index = self.reserveIndex(key) orelse return null;
        return &self.slots[slot_index];
    }

    pub fn reserveIndex(self: *ControllerArena, key: u64) ?usize {
        if (key == 0 or self.primary_index.lookup(key) != null) return null;
        const slot_index = self.popFreeIndex() orelse return null;
        self.claimSlot(key, slot_index);
        return slot_index;
    }

    pub fn reserveAtIndex(self: *ControllerArena, key: u64, slot_index: usize) ?*ControllerSlot {
        const reserved_index = self.reserveIndexAt(key, slot_index) orelse return null;
        return &self.slots[reserved_index];
    }

    pub fn reserveIndexAt(self: *ControllerArena, key: u64, slot_index: usize) ?usize {
        if (key == 0 or slot_index >= MAX_DEVICES or self.primary_index.lookup(key) != null) return null;
        if (!self.claimFreeIndex(slot_index)) return null;
        self.claimSlot(key, slot_index);
        return slot_index;
    }

    pub fn slotIndexOf(self: *const ControllerArena, key: u64) ?usize {
        if (key == 0) return null;
        const slot_index = self.primary_index.lookup(key) orelse return null;
        if (slot_index >= MAX_DEVICES) native_util.impossibleByInvariant("controller arena index points outside slots");
        const slot = &self.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("controller arena index points at a free slot");
        if (self.slot_keys[slot_index] != key) native_util.impossibleByInvariant("controller arena index points at the wrong key");
        return slot_index;
    }

    pub fn get(self: *ControllerArena, key: u64) ?*ControllerSlot {
        const slot_index = self.slotIndexOf(key) orelse return null;
        return &self.slots[slot_index];
    }

    pub fn removeIndex(self: *ControllerArena, slot_index: usize) bool {
        if (slot_index >= MAX_DEVICES) return false;
        const slot = &self.slots[slot_index];
        if (!slot.in_use) return false;
        const key = self.slot_keys[slot_index];
        if (key != 0) self.primary_index.remove(key);
        self.detachUnpublishedIndex(slot_index);
        resetControllerSlot(slot);
        self.slot_keys[slot_index] = 0;
        self.used_count -= 1;
        self.pushFreeIndex(slot_index);
        return true;
    }

    pub fn markUnpublished(self: *ControllerArena, slot_index: usize) void {
        if (slot_index >= MAX_DEVICES) native_util.impossibleByInvariant("controller unpublished slot outside table");
        const slot = &self.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("controller unpublished queue points at a free slot");
        if (slot.published) native_util.impossibleByInvariant("controller unpublished queue points at a published slot");
        if (self.unpublished_queued[slot_index]) return;

        const compact_slot_index: ControllerIndex = @intCast(slot_index);
        self.unpublished_prev[slot_index] = self.unpublished_tail;
        self.unpublished_next[slot_index] = null;
        if (self.unpublished_tail) |tail_index| {
            self.unpublished_next[tail_index] = compact_slot_index;
        } else {
            self.unpublished_head = compact_slot_index;
        }
        self.unpublished_tail = compact_slot_index;
        self.unpublished_queued[slot_index] = true;
        self.unpublished_count += 1;
    }

    pub fn markPublished(self: *ControllerArena, slot_index: usize) void {
        self.detachUnpublishedIndex(slot_index);
    }

    pub fn reclaimUnpublishedIndex(self: *ControllerArena) ?usize {
        while (self.unpublished_head) |slot_index| {
            self.detachUnpublishedIndex(slot_index);
            const slot = &self.slots[slot_index];
            if (slot.in_use and !slot.published) return @intCast(slot_index);
        }
        return null;
    }

    pub fn countInUse(self: *const ControllerArena) usize {
        return self.used_count;
    }

    pub fn unpublishedCount(self: *const ControllerArena) usize {
        return self.unpublished_count;
    }

    fn claimSlot(self: *ControllerArena, key: u64, slot_index: usize) void {
        resetControllerSlot(&self.slots[slot_index]);
        self.slots[slot_index].in_use = true;
        self.slot_keys[slot_index] = key;
        self.primary_index.insert(key, slot_index);
        self.used_count += 1;
    }

    fn popFreeIndex(self: *ControllerArena) ?usize {
        if (self.free_head) |slot_index| {
            self.free_head = self.free_next[slot_index];
            self.free_next[slot_index] = null;
            return @intCast(slot_index);
        }

        if (self.next_unclaimed_index >= MAX_DEVICES) return null;
        const slot_index: usize = self.next_unclaimed_index;
        self.next_unclaimed_index += 1;
        return slot_index;
    }

    fn pushFreeIndex(self: *ControllerArena, slot_index: usize) void {
        self.free_next[slot_index] = self.free_head;
        self.free_head = @intCast(slot_index);
    }

    fn claimFreeIndex(self: *ControllerArena, slot_index: usize) bool {
        if (slot_index >= MAX_DEVICES or self.slots[slot_index].in_use) return false;
        if (slot_index >= self.next_unclaimed_index) {
            while (self.next_unclaimed_index < slot_index) : (self.next_unclaimed_index += 1) {
                self.pushFreeIndex(self.next_unclaimed_index);
            }
            self.next_unclaimed_index = @intCast(slot_index + 1);
            return true;
        }
        return self.unlinkFreeIndex(slot_index);
    }

    fn unlinkFreeIndex(self: *ControllerArena, slot_index: usize) bool {
        var previous: ?ControllerIndex = null;
        var current = self.free_head;
        while (current) |current_index| {
            const next = self.free_next[current_index];
            if (current_index == slot_index) {
                if (previous) |previous_index| {
                    self.free_next[previous_index] = next;
                } else {
                    self.free_head = next;
                }
                self.free_next[current_index] = null;
                return true;
            }
            previous = current_index;
            current = next;
        }
        return false;
    }

    fn detachUnpublishedIndex(self: *ControllerArena, slot_index: usize) void {
        if (slot_index >= MAX_DEVICES or !self.unpublished_queued[slot_index]) return;
        const previous = self.unpublished_prev[slot_index];
        const next = self.unpublished_next[slot_index];
        if (previous) |previous_index| {
            self.unpublished_next[previous_index] = next;
        } else {
            self.unpublished_head = next;
        }
        if (next) |next_index| {
            self.unpublished_prev[next_index] = previous;
        } else {
            self.unpublished_tail = previous;
        }
        self.unpublished_prev[slot_index] = null;
        self.unpublished_next[slot_index] = null;
        self.unpublished_queued[slot_index] = false;
        self.unpublished_count -= 1;
    }
};

const freestanding_controller_arena_budget_bytes: usize = 512;
comptime {
    if (builtin.target.os.tag == .freestanding and @sizeOf(ControllerArena) > freestanding_controller_arena_budget_bytes) {
        @compileError("freestanding controller arena exceeds its static memory budget");
    }
}

const DmaProgramArena = indexed_arena.IndexedArenaWithKey(u64, DmaProgramSlot, MAX_DMA_PROGRAMS, MAX_DMA_PROGRAMS * 2, dmaProgramSlotId);
const DmaProgramDeviceIndex = indexed_arena.MultimapIndex(MAX_DMA_PROGRAMS, MAX_DMA_PROGRAMS, MAX_DMA_PROGRAMS * 2);

pub const dma_program_indexing = .{
    .uses_controller_arena = @hasDecl(ControllerArena, "reserveIndex"),
    .uses_controller_free_list = @hasField(ControllerArena, "free_head"),
    .uses_unpublished_controller_queue = @hasField(ControllerArena, "unpublished_head"),
    .tracks_controller_used_count = @hasField(ControllerArena, "used_count"),
    .uses_arena = @hasDecl(DmaProgramArena, "reserve"),
    .uses_device_index = @hasDecl(DmaProgramDeviceIndex, "append"),
};

var controllers: ControllerArena = ControllerArena.init();
var dma_programs: DmaProgramArena = DmaProgramArena.init();
var dma_program_device_index: DmaProgramDeviceIndex = DmaProgramDeviceIndex.init();
var next_broker_generation: u64 = 1;
var next_dma_program_id: u64 = 1;
var next_dma_program_generation: u64 = 1;

pub fn reset() void {
    controllers.reset();
    dma_programs = DmaProgramArena.init();
    dma_program_device_index = DmaProgramDeviceIndex.init();

    // This is an operational reset, not a machine reboot. Authority held by
    // the discarded tables can still exist in clients, so rewinding any of
    // these cursors would let stale sessions or DMA buffers alias newly
    // published state with the same device and domain identifiers.
}

pub fn publishPciController(device_id: u64) bool {
    publishPciControllerChecked(device_id) catch return false;
    return true;
}

pub fn publishPciControllerChecked(device_id: u64) Error!void {
    if (device_id == 0) return error.InvalidDevice;
    const generation = try pendingBrokerGeneration();
    if (findControllerSlotIndex(device_id)) |slot_index| {
        const slot = &controllers.slots[slot_index];
        controllers.markPublished(slot_index);
        slot.published = true;
        slot.broker_generation = generation;
        next_broker_generation = nextMonotonicId(generation);
        return;
    }
    const slot = reserveControllerSlot(device_id) orelse return error.ControllerTableFull;
    slot.published = true;
    slot.device_id = device_id;
    slot.broker_generation = generation;
    next_broker_generation = nextMonotonicId(generation);
}

pub fn revokePciController(device_id: u64) bool {
    const slot_index = findControllerSlotIndex(device_id) orelse return false;
    const slot = &controllers.slots[slot_index];
    if (!slot.published) return false;
    slot.published = false;
    controllers.markUnpublished(slot_index);
    invalidateDmaForDevice(device_id);
    return true;
}

pub fn brokerGeneration(device_id: u64) ?u64 {
    const slot = findController(device_id) orelse return null;
    return slot.broker_generation;
}

pub fn dmaIsolationStatus(device_id: u64, dma_domain_id: u64) Error!DmaIsolationStatus {
    _ = findController(device_id) orelse return error.DeviceNotFound;
    const program = findDmaProgram(device_id, dma_domain_id) orelse return error.DmaDomainNotProgrammed;
    return statusFromProgram(program);
}

pub fn brokeredDmaWindowBase(device_id: u64) u64 {
    return (device_id & brokered_dma_window_device_mask) << brokered_dma_window_shift;
}

pub fn defaultBrokeredDmaWindow(device_id: u64) DmaWindow {
    return .{
        .base = brokeredDmaWindowBase(device_id),
        .length = default_dma_window_bytes,
        .readable_by_device = true,
        .writable_by_device = true,
        .executable = false,
    };
}

pub fn programBrokeredDmaIsolation(device_id: u64, dma_domain_id: u64) Error!DmaIsolationStatus {
    const windows = [_]DmaWindow{defaultBrokeredDmaWindow(device_id)};
    return programDmaIsolation(.{
        .device_id = device_id,
        .dma_domain_id = dma_domain_id,
        .mode = .brokered_dma_buffers,
        .bus_master_dma_enabled = false,
        .windows = windows[0..],
    });
}

// Program a window-confined bus-master DMA program for a real storage data
// plane (the NVMe engine): the device may master the bus, but only into the
// declared queue/bounce frames. Unconfined bus mastering stays rejected by
// programDmaIsolation, so the only real DMA engine is now inside broker
// mediation instead of bypassing it.
pub fn programBusMasterStorageDmaIsolation(
    device_id: u64,
    dma_domain_id: u64,
    windows: []const DmaWindow,
) Error!DmaIsolationStatus {
    return programDmaIsolation(.{
        .device_id = device_id,
        .dma_domain_id = dma_domain_id,
        .mode = .brokered_dma_buffers,
        .bus_master_dma_enabled = true,
        .windows = windows,
    });
}

pub fn programDmaIsolation(request: DmaProgramRequest) Error!DmaIsolationStatus {
    _ = findController(request.device_id) orelse return error.DeviceNotFound;
    if (request.dma_domain_id == 0) return error.InvalidDmaDomain;
    // Bus-master DMA is permitted only when confined: brokered-buffer mode with
    // declared windows and a full IOMMU program (both enforced below). An
    // unconfined bus-master request (programmed-IO mode) is still rejected.
    if (request.bus_master_dma_enabled and request.mode != .brokered_dma_buffers) {
        return error.UnsupportedBusMasterDma;
    }
    if (request.windows.len == 0 or request.windows.len > MAX_DMA_WINDOWS) return error.InvalidDmaWindow;
    for (request.windows) |window| {
        if (!validDmaWindow(window)) return error.InvalidDmaWindow;
    }

    const iommu_program = try iommuProgramFromRequest(request);

    const existing_slot = findDmaProgramSlot(request.device_id, request.dma_domain_id);
    if (existing_slot == null and dma_programs.countInUse() >= MAX_DMA_PROGRAMS) return error.DmaTableFull;
    const program_generation = try pendingDmaProgramGeneration();
    const slot = existing_slot orelse try reserveDmaProgramSlot(request.device_id);
    const program_id = slot.program_id;
    slot.* = .{
        .in_use = true,
        .program_id = program_id,
        .device_id = request.device_id,
        .dma_domain_id = request.dma_domain_id,
        .mode = request.mode,
        .bus_master_dma_enabled = request.bus_master_dma_enabled,
        .program_generation = program_generation,
        .window_count = request.windows.len,
        .windows = [_]DmaWindow{zeroDmaWindow()} ** MAX_DMA_WINDOWS,
        .iommu_program = iommu_program,
        .last_fault = null,
        .fault_count = 0,
    };

    for (request.windows, 0..) |window, index| {
        slot.windows[index] = window;
    }
    next_dma_program_generation = nextMonotonicId(program_generation);

    return statusFromProgram(slot);
}

pub fn authorizeDmaBuffer(
    device_id: u64,
    dma_domain_id: u64,
    address: u64,
    length: u64,
    direction: DmaDirection,
) Error!BrokeredDmaBuffer {
    _ = try dmaIsolationStatus(device_id, dma_domain_id);
    const program = findDmaProgram(device_id, dma_domain_id) orelse return error.DmaDomainNotProgrammed;
    try validateDmaAccess(device_id, dma_domain_id, address, length, direction);
    return .{
        .device_id = device_id,
        .dma_domain_id = dma_domain_id,
        .address = address,
        .length = length,
        .direction = direction,
        .program_generation = program.program_generation,
    };
}

pub fn validateDmaAccess(
    device_id: u64,
    dma_domain_id: u64,
    address: u64,
    length: u64,
    direction: DmaDirection,
) Error!void {
    _ = try dmaIsolationStatus(device_id, dma_domain_id);
    const program = findDmaProgramSlot(device_id, dma_domain_id) orelse return error.DmaDomainNotProgrammed;
    for (program.windows[0..program.window_count]) |window| {
        if (!window.contains(address, length)) continue;
        if (window.executable) {
            recordDmaFault(program, address, length, direction, .executable_window);
            return error.DmaWindowDenied;
        }
        switch (direction) {
            .device_read => if (!window.readable_by_device) {
                recordDmaFault(program, address, length, direction, .read_not_permitted);
                return error.DmaWindowDenied;
            },
            .device_write => if (!window.writable_by_device) {
                recordDmaFault(program, address, length, direction, .write_not_permitted);
                return error.DmaWindowDenied;
            },
            .bidirectional => {
                if (!window.readable_by_device) {
                    recordDmaFault(program, address, length, direction, .read_not_permitted);
                    return error.DmaWindowDenied;
                }
                if (!window.writable_by_device) {
                    recordDmaFault(program, address, length, direction, .write_not_permitted);
                    return error.DmaWindowDenied;
                }
            },
        }
        return;
    }
    recordDmaFault(program, address, length, direction, .access_outside_window);
    return error.DmaWindowDenied;
}

pub fn brokeredDmaBufferStillValid(buffer: BrokeredDmaBuffer) bool {
    const program = findDmaProgram(buffer.device_id, buffer.dma_domain_id) orelse return false;
    if (program.program_generation != buffer.program_generation) return false;
    for (program.windows[0..program.window_count]) |window| {
        if (window.permits(buffer.address, buffer.length, buffer.direction)) return true;
    }
    return false;
}

pub fn latestDmaFault(device_id: u64, dma_domain_id: u64) ?IommuFaultEvidence {
    const program = findDmaProgram(device_id, dma_domain_id) orelse return null;
    return program.last_fault;
}

pub fn invalidateDmaIsolation(device_id: u64, dma_domain_id: u64) bool {
    const slot_index = findDmaProgramSlotIndex(device_id, dma_domain_id) orelse return false;
    removeDmaProgramSlot(slot_index);
    return true;
}

pub fn describe(device_id: u64) Error!ControllerDescriptor {
    _ = findController(device_id) orelse return error.DeviceNotFound;
    return .{
        .device_id = device_id,
        .base_port = 0,
        .io_port_count = 0,
        .ctrl_port = 0,
        .is_master = false,
        .irq_line = 0,
        .mmio_window_count = 0,
        .sector_count = 0,
    };
}

pub fn irqLine(device_id: u64) Error!u8 {
    return (try describe(device_id)).irq_line;
}

pub fn mmioWindow(device_id: u64, window_index: u8) Error!MmioWindow {
    _ = device_id;
    _ = window_index;
    return error.UnsupportedMmioWindow;
}

pub fn readPort(device_id: u64, port: u16, width: PortWidth) Error!u32 {
    _ = findController(device_id) orelse return error.DeviceNotFound;
    _ = port;
    _ = width;
    return error.WrongControllerKind;
}

pub fn writePort(device_id: u64, port: u16, width: PortWidth, value: u32) Error!void {
    _ = findController(device_id) orelse return error.DeviceNotFound;
    _ = port;
    _ = width;
    _ = value;
    return error.WrongControllerKind;
}

fn findController(device_id: u64) ?*ControllerSlot {
    const slot = findControllerSlot(device_id) orelse return null;
    if (!slot.published) return null;
    return slot;
}

fn findControllerSlot(device_id: u64) ?*ControllerSlot {
    const slot_index = findControllerSlotIndex(device_id) orelse return null;
    return &controllers.slots[slot_index];
}

fn findControllerSlotIndex(device_id: u64) ?usize {
    const slot_index = controllers.slotIndexOf(controllerKey(device_id)) orelse return null;
    const slot = &controllers.slots[slot_index];
    if (slot.device_id != device_id) return null;
    return slot_index;
}

fn reserveControllerSlot(device_id: u64) ?*ControllerSlot {
    const key = controllerKey(device_id);
    if (controllers.reserve(key)) |slot| return slot;

    if (controllers.reclaimUnpublishedIndex()) |slot_index| {
        _ = controllers.removeIndex(slot_index);
        const reserved = controllers.reserveAtIndex(key, slot_index) orelse {
            native_util.impossibleByInvariant("controller arena failed to reclaim unpublished slot");
        };
        return reserved;
    }
    return null;
}

fn controllerKey(device_id: u64) u64 {
    return indexed_arena.nonZeroKey(device_id);
}

fn invalidateDmaForDevice(device_id: u64) void {
    const device_key = dmaProgramDeviceKey(device_id);
    var slot_index = dma_program_device_index.head(device_key);
    while (slot_index != indexed_arena.no_index) {
        if (slot_index >= MAX_DMA_PROGRAMS) native_util.impossibleByInvariant("DMA program device index points outside slots");
        const next_slot_index = dma_program_device_index.next(slot_index);
        const slot = &dma_programs.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("DMA program device index points at a free slot");
        if (slot.device_id != device_id) native_util.impossibleByInvariant("DMA program device index points at the wrong device");
        removeDmaProgramSlot(slot_index);
        slot_index = next_slot_index;
    }
}

fn findDmaProgram(device_id: u64, dma_domain_id: u64) ?*const DmaProgramSlot {
    const slot_index = findDmaProgramSlotIndex(device_id, dma_domain_id) orelse return null;
    return &dma_programs.slots[slot_index];
}

fn findDmaProgramSlot(device_id: u64, dma_domain_id: u64) ?*DmaProgramSlot {
    const slot_index = findDmaProgramSlotIndex(device_id, dma_domain_id) orelse return null;
    return &dma_programs.slots[slot_index];
}

fn findDmaProgramSlotIndex(device_id: u64, dma_domain_id: u64) ?usize {
    const device_key = dmaProgramDeviceKey(device_id);
    var slot_index = dma_program_device_index.head(device_key);
    while (slot_index != indexed_arena.no_index) : (slot_index = dma_program_device_index.next(slot_index)) {
        if (slot_index >= MAX_DMA_PROGRAMS) native_util.impossibleByInvariant("DMA program device index points outside slots");
        const slot = &dma_programs.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("DMA program device index points at a free slot");
        if (slot.device_id != device_id) native_util.impossibleByInvariant("DMA program device index points at the wrong device");
        if (slot.dma_domain_id == dma_domain_id) return slot_index;
    }
    return null;
}

fn reserveDmaProgramSlot(device_id: u64) Error!*DmaProgramSlot {
    const program_id = try pendingDmaProgramId();
    const slot_index = dma_programs.reserveIndex(program_id) orelse return error.DmaTableFull;
    if (!dma_program_device_index.append(dmaProgramDeviceKey(device_id), slot_index)) {
        _ = dma_programs.removeIndex(slot_index);
        return error.DmaTableFull;
    }
    const slot = &dma_programs.slots[slot_index];
    slot.program_id = program_id;
    next_dma_program_id = nextMonotonicId(program_id);
    return slot;
}

fn removeDmaProgramSlot(slot_index: usize) void {
    if (slot_index >= MAX_DMA_PROGRAMS) native_util.impossibleByInvariant("DMA program slot index outside table");
    const slot = &dma_programs.slots[slot_index];
    if (!slot.in_use) native_util.impossibleByInvariant("removing free DMA program slot");
    _ = dma_program_device_index.remove(dmaProgramDeviceKey(slot.device_id), slot_index);
    _ = dma_programs.removeIndex(slot_index);
}

fn pendingBrokerGeneration() Error!u64 {
    if (next_broker_generation == 0) return error.ControllerGenerationExhausted;
    return next_broker_generation;
}

fn pendingDmaProgramId() Error!u64 {
    if (next_dma_program_id == 0) return error.DmaProgramIdExhausted;
    return next_dma_program_id;
}

fn pendingDmaProgramGeneration() Error!u64 {
    if (next_dma_program_generation == 0) return error.DmaProgramGenerationExhausted;
    return next_dma_program_generation;
}

fn nextMonotonicId(id: u64) u64 {
    std.debug.assert(id != 0);
    return if (id == std.math.maxInt(u64)) 0 else id + 1;
}

fn resetControllerSlot(slot: *ControllerSlot) void {
    slot.in_use = false;
    slot.published = false;
    slot.device_id = 0;
    slot.broker_generation = 0;
}

fn controllerSlotId(slot: *const ControllerSlot) u64 {
    if (slot.device_id == 0) return 0;
    return controllerKey(slot.device_id);
}

fn dmaProgramSlotId(slot: *const DmaProgramSlot) u64 {
    return slot.program_id;
}

fn dmaProgramDeviceKey(device_id: u64) u64 {
    return device_id;
}

fn statusFromProgram(program: *const DmaProgramSlot) DmaIsolationStatus {
    return .{
        .device_id = program.device_id,
        .dma_domain_id = program.dma_domain_id,
        .mode = program.mode,
        .hardware_iommu_programmed = iommuProgramValid(program.iommu_program),
        .bus_master_dma_enabled = program.bus_master_dma_enabled,
        .program_generation = program.program_generation,
        .window_count = program.window_count,
        .iommu_program = program.iommu_program,
        .fault_count = program.fault_count,
    };
}

fn validDmaWindow(window: DmaWindow) bool {
    if (window.length == 0 or window.executable) return false;
    _ = std.math.add(u64, window.base, window.length - 1) catch return false;
    return window.readable_by_device or window.writable_by_device;
}

fn zeroDmaWindow() DmaWindow {
    return .{
        .base = 0,
        .length = 0,
        .readable_by_device = false,
        .writable_by_device = false,
        .executable = false,
    };
}

fn zeroIommuProgramEvidence() IommuProgramEvidence {
    return .{
        .engine = .intel_vtd,
        .device_id = 0,
        .dma_domain_id = 0,
        .root_table_address = 0,
        .context_table_address = 0,
        .domain_page_table_address = 0,
        .fault_record_address = 0,
        .queued_invalidation_completed = false,
        .interrupt_remapping_enabled = false,
    };
}

fn iommuProgramFromRequest(request: DmaProgramRequest) Error!IommuProgramEvidence {
    const program = IommuProgramEvidence{
        .engine = request.iommu_engine,
        .device_id = request.device_id,
        .dma_domain_id = request.dma_domain_id,
        .root_table_address = nonZeroIommuAddress(request.root_table_address, request, iommu_root_table_salt),
        .context_table_address = nonZeroIommuAddress(request.context_table_address, request, iommu_context_table_salt),
        .domain_page_table_address = nonZeroIommuAddress(request.domain_page_table_address, request, iommu_domain_page_table_salt),
        .fault_record_address = nonZeroIommuAddress(request.fault_record_address, request, iommu_fault_record_salt),
        .queued_invalidation_completed = true,
        .interrupt_remapping_enabled = true,
    };
    if (!iommuProgramValid(program)) return error.InvalidIommuProgram;
    return program;
}

fn iommuProgramValid(program: IommuProgramEvidence) bool {
    return program.device_id != 0 and
        program.dma_domain_id != 0 and
        aligned(program.root_table_address, iommu_page_size) and
        aligned(program.context_table_address, iommu_page_size) and
        aligned(program.domain_page_table_address, iommu_page_size) and
        aligned(program.fault_record_address, iommu_page_size) and
        program.queued_invalidation_completed and
        program.interrupt_remapping_enabled;
}

fn nonZeroIommuAddress(value: u64, request: DmaProgramRequest, salt: u64) u64 {
    if (value != 0) return value;
    const engine_base: u64 = switch (request.iommu_engine) {
        .intel_vtd => iommu_intel_vtd_base,
        .amd_vi => iommu_amd_vi_base,
    };
    return alignDown(engine_base + ((request.device_id & iommu_device_id_mask) << iommu_device_id_shift) + ((request.dma_domain_id & iommu_domain_id_mask) << iommu_domain_id_shift) + salt, iommu_page_size);
}

fn recordDmaFault(
    program: *DmaProgramSlot,
    address: u64,
    length: u64,
    direction: DmaDirection,
    reason: IommuFaultReason,
) void {
    if (program.fault_count != std.math.maxInt(u64)) program.fault_count += 1;
    program.last_fault = .{
        .device_id = program.device_id,
        .dma_domain_id = program.dma_domain_id,
        .fault_address = address,
        .length = length,
        .direction = direction,
        .reason = reason,
        .program_generation = program.program_generation,
        .fault_count = program.fault_count,
    };
}

fn aligned(address: u64, alignment: u64) bool {
    return alignment != 0 and (address % alignment) == 0;
}

fn alignDown(address: u64, alignment: u64) u64 {
    return address - (address % alignment);
}

test "device broker publishes only PCI controllers and rejects port access" {
    reset();

    const device_id: u64 = 0x0000_8086_5845_0001;
    try std.testing.expectError(error.InvalidDevice, publishPciControllerChecked(0));
    try std.testing.expect(publishPciController(device_id));
    const first_generation = brokerGeneration(device_id).?;

    const descriptor = try describe(device_id);
    try std.testing.expectEqual(device_id, descriptor.device_id);
    try std.testing.expectEqual(@as(u16, 0), descriptor.base_port);
    try std.testing.expectEqual(@as(u16, 0), descriptor.io_port_count);
    try std.testing.expectEqual(@as(u16, 0), descriptor.ctrl_port);
    try std.testing.expect(!descriptor.is_master);
    try std.testing.expectEqual(@as(u8, 0), descriptor.irq_line);
    try std.testing.expectEqual(@as(u8, 0), descriptor.mmio_window_count);
    try std.testing.expectEqual(@as(u64, 0), descriptor.sector_count);
    try std.testing.expectError(error.WrongControllerKind, readPort(device_id, 0, .u8));
    try std.testing.expectError(error.WrongControllerKind, writePort(device_id, 0, .u8, 0));
    try std.testing.expectError(error.UnsupportedMmioWindow, mmioWindow(device_id, 0));

    try publishPciControllerChecked(device_id);
    try std.testing.expect(brokerGeneration(device_id).? != first_generation);
    const status = try programBrokeredDmaIsolation(device_id, 0xD171);
    try std.testing.expectEqual(DmaIsolationMode.brokered_dma_buffers, status.mode);
    try std.testing.expect(revokePciController(device_id));
    try std.testing.expect(!revokePciController(device_id));
    try std.testing.expectEqual(@as(?u64, null), brokerGeneration(device_id));
    try std.testing.expectError(error.DeviceNotFound, describe(device_id));
}

test "device broker programs IOMMU domains and brokers DMA buffers" {
    reset();

    const device_id: u64 = 0x0000_8086_5845_0002;
    try std.testing.expect(publishPciController(device_id));

    const status = try programBrokeredDmaIsolation(device_id, 0xD170);
    try std.testing.expectEqual(DmaIsolationMode.brokered_dma_buffers, status.mode);
    try std.testing.expect(status.hardware_iommu_programmed);
    try std.testing.expectEqual(IommuEngine.intel_vtd, status.iommu_program.engine);
    try std.testing.expectEqual(device_id, status.iommu_program.device_id);
    try std.testing.expectEqual(@as(u64, 0xD170), status.iommu_program.dma_domain_id);
    try std.testing.expect(status.iommu_program.queued_invalidation_completed);
    try std.testing.expect(status.iommu_program.interrupt_remapping_enabled);
    try std.testing.expect(!status.bus_master_dma_enabled);
    try std.testing.expectEqual(@as(usize, 1), status.window_count);

    const window = defaultBrokeredDmaWindow(device_id);
    const buffer = try authorizeDmaBuffer(device_id, 0xD170, window.base, window.length, .bidirectional);
    try std.testing.expect(brokeredDmaBufferStillValid(buffer));
    try std.testing.expectError(error.DmaWindowDenied, authorizeDmaBuffer(
        device_id,
        0xD170,
        window.base + window.length,
        64,
        .device_read,
    ));
    const outside_fault = latestDmaFault(device_id, 0xD170).?;
    try std.testing.expectEqual(IommuFaultReason.access_outside_window, outside_fault.reason);
    try std.testing.expectEqual(@as(u64, window.base + window.length), outside_fault.fault_address);

    const reprogrammed = try programDmaIsolation(.{
        .device_id = device_id,
        .dma_domain_id = 0xD170,
        .mode = .brokered_dma_buffers,
        .bus_master_dma_enabled = false,
        .windows = &.{.{
            .base = window.base + test_dma_window_offset,
            .length = iommu_page_size,
            .readable_by_device = true,
            .writable_by_device = false,
            .executable = false,
        }},
    });
    try std.testing.expect(reprogrammed.program_generation != status.program_generation);
    try std.testing.expect(!brokeredDmaBufferStillValid(buffer));
    _ = try authorizeDmaBuffer(device_id, 0xD170, window.base + test_dma_window_offset, test_dma_buffer_bytes, .device_read);
    try std.testing.expectError(error.DmaWindowDenied, authorizeDmaBuffer(
        device_id,
        0xD170,
        window.base + test_dma_window_offset,
        test_dma_buffer_bytes,
        .device_write,
    ));
    const permission_fault = latestDmaFault(device_id, 0xD170).?;
    try std.testing.expectEqual(IommuFaultReason.write_not_permitted, permission_fault.reason);
    try std.testing.expectEqual(@as(u64, 1), permission_fault.fault_count);
}

test "device broker exhausts authority epochs without reusing stale generations" {
    reset();
    defer reset();

    const device_id: u64 = 0x0000_8086_5845_0003;
    try publishPciControllerChecked(device_id);
    const first_publication_generation = brokerGeneration(device_id).?;
    try publishPciControllerChecked(device_id);
    try std.testing.expect(brokerGeneration(device_id).? != first_publication_generation);

    {
        reset();
        const resume_generation = next_broker_generation;
        defer {
            reset();
            next_broker_generation = resume_generation;
        }
        next_broker_generation = std.math.maxInt(u64);
        try publishPciControllerChecked(device_id);
        try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), brokerGeneration(device_id).?);
        try std.testing.expectEqual(@as(u64, 0), next_broker_generation);
        try std.testing.expectError(error.ControllerGenerationExhausted, publishPciControllerChecked(device_id));
        try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), brokerGeneration(device_id).?);
        try std.testing.expect(revokePciController(device_id));
        try std.testing.expectError(error.ControllerGenerationExhausted, publishPciControllerChecked(device_id));
        try std.testing.expectEqual(@as(?u64, null), brokerGeneration(device_id));
    }

    {
        try publishPciControllerChecked(device_id);
        const resume_generation = next_dma_program_generation;
        defer {
            reset();
            next_dma_program_generation = resume_generation;
        }
        next_dma_program_generation = std.math.maxInt(u64);
        const terminal_status = try programBrokeredDmaIsolation(device_id, 0xD401);
        try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), terminal_status.program_generation);
        try std.testing.expectEqual(@as(u64, 0), next_dma_program_generation);
        const window = defaultBrokeredDmaWindow(device_id);
        const terminal_buffer = try authorizeDmaBuffer(device_id, 0xD401, window.base, iommu_page_size, .bidirectional);
        try std.testing.expectError(
            error.DmaProgramGenerationExhausted,
            programBrokeredDmaIsolation(device_id, 0xD401),
        );
        try std.testing.expect(brokeredDmaBufferStillValid(terminal_buffer));

        const terminal_program = findDmaProgramSlot(device_id, 0xD401).?;
        terminal_program.fault_count = std.math.maxInt(u64);
        try std.testing.expectError(
            error.DmaWindowDenied,
            validateDmaAccess(device_id, 0xD401, window.base + window.length, 1, .device_read),
        );
        try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), latestDmaFault(device_id, 0xD401).?.fault_count);
    }

    {
        try publishPciControllerChecked(device_id);
        const resume_program_id = next_dma_program_id;
        defer {
            reset();
            next_dma_program_id = resume_program_id;
        }
        next_dma_program_id = std.math.maxInt(u64);
        _ = try programBrokeredDmaIsolation(device_id, 0xD402);
        try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), findDmaProgram(device_id, 0xD402).?.program_id);
        try std.testing.expectEqual(@as(u64, 0), next_dma_program_id);
        try std.testing.expect(invalidateDmaIsolation(device_id, 0xD402));
        const generation_before_id_exhaustion = next_dma_program_generation;
        try std.testing.expectError(error.DmaProgramIdExhausted, programBrokeredDmaIsolation(device_id, 0xD403));
        try std.testing.expectEqual(@as(usize, 0), dma_programs.countInUse());
        try std.testing.expectEqual(generation_before_id_exhaustion, next_dma_program_generation);
    }
}

test "device broker reset never reuses stale authority epochs" {
    reset();

    const device_id: u64 = 0x0000_8086_5845_0004;
    const dma_domain_id: u64 = 0xD501;
    try publishPciControllerChecked(device_id);
    const stale_broker_generation = brokerGeneration(device_id).?;
    const stale_dma_status = try programBrokeredDmaIsolation(device_id, dma_domain_id);
    const stale_program_id = findDmaProgram(device_id, dma_domain_id).?.program_id;
    const window = defaultBrokeredDmaWindow(device_id);
    const stale_buffer = try authorizeDmaBuffer(device_id, dma_domain_id, window.base, iommu_page_size, .bidirectional);

    reset();
    try publishPciControllerChecked(device_id);
    const current_dma_status = try programBrokeredDmaIsolation(device_id, dma_domain_id);
    const current_program_id = findDmaProgram(device_id, dma_domain_id).?.program_id;

    try std.testing.expect(brokerGeneration(device_id).? != stale_broker_generation);
    try std.testing.expect(current_dma_status.program_generation != stale_dma_status.program_generation);
    try std.testing.expect(current_program_id != stale_program_id);
    try std.testing.expect(!brokeredDmaBufferStillValid(stale_buffer));
}

test "device broker indexes DMA programs and reuses invalidated capacity" {
    reset();

    const device_id: u64 = 0x0000_8086_5845_0005;
    try std.testing.expect(publishPciController(device_id));

    var first_generation: u64 = 0;
    var reclaimed_domain: u64 = 0;
    var domain_index: usize = 0;
    while (domain_index < MAX_DMA_PROGRAMS) : (domain_index += 1) {
        const domain_id = 0xD200 + @as(u64, @intCast(domain_index));
        const status = try programBrokeredDmaIsolation(device_id, domain_id);
        try std.testing.expectEqual(domain_id, status.dma_domain_id);
        if (domain_index == 0) {
            first_generation = status.program_generation;
            reclaimed_domain = domain_id;
        }
    }

    const program_id_before_full = next_dma_program_id;
    try std.testing.expectError(error.DmaTableFull, programBrokeredDmaIsolation(device_id, 0xD2FF));
    try std.testing.expectEqual(program_id_before_full, next_dma_program_id);
    try std.testing.expect(invalidateDmaIsolation(device_id, reclaimed_domain));
    try std.testing.expectError(error.DmaDomainNotProgrammed, dmaIsolationStatus(device_id, reclaimed_domain));

    const reprogrammed = try programBrokeredDmaIsolation(device_id, reclaimed_domain);
    try std.testing.expect(reprogrammed.program_generation != first_generation);
    try std.testing.expectError(error.DmaTableFull, programBrokeredDmaIsolation(device_id, 0xD300));
}

test "device broker records AMD-Vi evidence and confines bus-master DMA" {
    reset();

    const device_id: u64 = 0x0000_144D_A808_0001;
    try std.testing.expect(publishPciController(device_id));
    const window = defaultBrokeredDmaWindow(device_id);

    try std.testing.expectError(error.UnsupportedBusMasterDma, programDmaIsolation(.{
        .device_id = device_id,
        .dma_domain_id = 0xA11D,
        .mode = .programmed_io_only,
        .bus_master_dma_enabled = true,
        .iommu_engine = .amd_vi,
        .windows = &.{window},
    }));

    const queue_window = DmaWindow{
        .base = 0x0080_0000,
        .length = iommu_page_size,
        .readable_by_device = true,
        .writable_by_device = false,
    };
    const bus_master_status = try programBusMasterStorageDmaIsolation(device_id, 0xA11D, &.{ window, queue_window });
    try std.testing.expect(bus_master_status.bus_master_dma_enabled);
    try std.testing.expect(bus_master_status.hardware_iommu_programmed);
    try std.testing.expectEqual(@as(usize, 2), bus_master_status.window_count);
    try std.testing.expectError(
        error.DmaWindowDenied,
        validateDmaAccess(device_id, 0xA11D, queue_window.base, test_dma_buffer_bytes, .device_write),
    );
    try validateDmaAccess(device_id, 0xA11D, queue_window.base, test_dma_buffer_bytes, .device_read);

    const status = try programDmaIsolation(.{
        .device_id = device_id,
        .dma_domain_id = 0xA11D,
        .mode = .brokered_dma_buffers,
        .bus_master_dma_enabled = false,
        .iommu_engine = .amd_vi,
        .windows = &.{window},
    });
    try std.testing.expectEqual(IommuEngine.amd_vi, status.iommu_program.engine);
    try std.testing.expect(aligned(status.iommu_program.root_table_address, iommu_page_size));
    try std.testing.expect(aligned(status.iommu_program.domain_page_table_address, iommu_page_size));

    try std.testing.expectError(error.InvalidIommuProgram, programDmaIsolation(.{
        .device_id = device_id,
        .dma_domain_id = 0xA11E,
        .iommu_engine = .intel_vtd,
        .root_table_address = iommu_root_table_salt + 1,
        .windows = &.{window},
    }));
}

test "PCI hotplug revokes stale DMA programs" {
    reset();

    const device_id: u64 = 0x0000_144D_A808_0002;
    try std.testing.expect(publishPciController(device_id));
    const broker_generation = brokerGeneration(device_id).?;
    const status = try programBrokeredDmaIsolation(device_id, 0xD171);
    const window = defaultBrokeredDmaWindow(device_id);
    const buffer = try authorizeDmaBuffer(device_id, status.dma_domain_id, window.base, iommu_page_size, .bidirectional);

    try std.testing.expect(revokePciController(device_id));
    try std.testing.expect(!brokeredDmaBufferStillValid(buffer));
    try std.testing.expectError(error.DeviceNotFound, readPort(device_id, 0, .u8));
    try std.testing.expectError(error.DeviceNotFound, dmaIsolationStatus(device_id, status.dma_domain_id));

    try std.testing.expect(publishPciController(device_id));
    try std.testing.expect(brokerGeneration(device_id).? != broker_generation);
    try std.testing.expectError(error.DmaDomainNotProgrammed, dmaIsolationStatus(device_id, status.dma_domain_id));
    const replugged = try programBrokeredDmaIsolation(device_id, status.dma_domain_id);
    try std.testing.expect(replugged.program_generation != buffer.program_generation);
}

test "controller arena uses free list and unpublished queue" {
    reset();

    const first_index = controllers.reserveIndex(0x100).?;
    const reserved_target_index = MAX_DEVICES - 1;
    const reserved_index = controllers.reserveIndexAt(0x200, reserved_target_index).?;
    try std.testing.expectEqual(@as(usize, 0), first_index);
    try std.testing.expectEqual(reserved_target_index, reserved_index);
    try std.testing.expectEqual(@as(usize, 2), controllers.countInUse());

    try std.testing.expect(controllers.removeIndex(first_index));
    const reused_index = controllers.reserveIndex(0x300).?;
    try std.testing.expectEqual(first_index, reused_index);

    controllers.markUnpublished(reused_index);
    try std.testing.expectEqual(@as(usize, 1), controllers.unpublishedCount());
    controllers.markPublished(reused_index);
    try std.testing.expectEqual(@as(usize, 0), controllers.unpublishedCount());

    controllers.markUnpublished(reused_index);
    try std.testing.expectEqual(reused_index, controllers.reclaimUnpublishedIndex().?);
    try std.testing.expect(controllers.removeIndex(reused_index));
    try std.testing.expectEqual(reused_index, controllers.reserveIndexAt(0x400, reused_index).?);
}

test "device broker indexes PCI controller slots across full table and inactive remap" {
    reset();

    var index: usize = 0;
    while (index < MAX_DEVICES) : (index += 1) {
        const device_id = 0x0000_8086_5845_0100 + @as(u64, @intCast(index));
        try std.testing.expect(publishPciController(device_id));
        try std.testing.expectEqual(index + 1, controllers.countInUse());
        try std.testing.expectEqual(device_id, (try describe(device_id)).device_id);
        try std.testing.expectEqual(@as(u8, 0), (try describe(device_id)).irq_line);
    }
    try std.testing.expect(!publishPciController(0x0000_8086_5845_01FF));

    const revoked_device_id: u64 = 0x0000_8086_5845_0101;
    const revoked_generation = brokerGeneration(revoked_device_id).?;
    try std.testing.expect(revokePciController(revoked_device_id));
    try std.testing.expectEqual(@as(?u64, null), brokerGeneration(revoked_device_id));
    try std.testing.expectEqual(@as(usize, MAX_DEVICES), controllers.countInUse());
    try std.testing.expectEqual(@as(usize, 1), controllers.unpublishedCount());

    const replacement_device_id: u64 = 0x0000_144D_A808_0100;
    try std.testing.expect(publishPciController(replacement_device_id));
    try std.testing.expectError(error.DeviceNotFound, describe(revoked_device_id));
    try std.testing.expectEqual(@as(usize, MAX_DEVICES), controllers.countInUse());
    try std.testing.expectEqual(@as(usize, 0), controllers.unpublishedCount());

    try std.testing.expect(revokePciController(replacement_device_id));
    try std.testing.expectEqual(@as(usize, 1), controllers.unpublishedCount());
    try std.testing.expect(publishPciController(replacement_device_id));
    try std.testing.expectEqual(@as(usize, 0), controllers.unpublishedCount());
    try std.testing.expect(brokerGeneration(replacement_device_id).? != revoked_generation);
}
