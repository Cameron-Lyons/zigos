//! xHCI DMA arena planning: ring, context, scratchpad and report-buffer
//! layout, initialization and the device-visible access regions.

const std = @import("std");
const xhci = @import("../xhci.zig");

const COMMAND_RING_INITIAL_CYCLE_STATE = xhci.trb.COMMAND_RING_INITIAL_CYCLE_STATE;
const COMMAND_RING_TRBS = xhci.COMMAND_RING_TRBS;
const CapabilityRegisters = xhci.CapabilityRegisters;
const DCBAA_ENTRY_BYTES = xhci.DCBAA_ENTRY_BYTES;
const DEVICE_CONTEXT_ENTRIES = xhci.DEVICE_CONTEXT_ENTRIES;
const ERST_TABLE_ALIGNMENT_BYTES = xhci.ERST_TABLE_ALIGNMENT_BYTES;
const EVENT_RING_SEGMENT_TABLE_ENTRIES = xhci.EVENT_RING_SEGMENT_TABLE_ENTRIES;
const EVENT_RING_TRBS = xhci.EVENT_RING_TRBS;
const Error = xhci.Error;
const INPUT_CONTEXT_ENTRIES = xhci.INPUT_CONTEXT_ENTRIES;
const INTERRUPT_REPORT_BUFFER_STRIDE = xhci.INTERRUPT_REPORT_BUFFER_STRIDE;
const LINK_TRB_TOGGLE_CYCLE = xhci.trb.LINK_TRB_TOGGLE_CYCLE;
const LINK_TRB_TYPE = xhci.trb.LINK_TRB_TYPE;
const MAX_CONTROLLER_DMA_REGIONS = xhci.MAX_CONTROLLER_DMA_REGIONS;
const RingPlan = xhci.RingPlan;
const SCRATCHPAD_ARRAY_ENTRY_BYTES = xhci.SCRATCHPAD_ARRAY_ENTRY_BYTES;
const TEST_MAX_DEVICE_SLOTS = xhci.TEST_MAX_DEVICE_SLOTS;
const TRANSFER_RING_TRBS = xhci.TRANSFER_RING_TRBS;
const TRB_BYTES = xhci.TRB_BYTES;
const TRB_TYPE_SHIFT = xhci.trb.TRB_TYPE_SHIFT;
const USB_ENUMERATION_BUFFER_BYTES = xhci.USB_ENUMERATION_BUFFER_BYTES;
const XHCI_PAGE_BYTES = xhci.XHCI_PAGE_BYTES;
const XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES = xhci.XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES;
const aligned = xhci.aligned;
const defaultCapabilityRegisters = xhci.defaultCapabilityRegisters;
const maxDeviceSlotsU8 = xhci.maxDeviceSlotsU8;
const ringEndAddress = xhci.ringEndAddress;
const ringLinkControl = xhci.trb.ringLinkControl;
const validateRing = xhci.validateRing;
const validateRingPlan = xhci.validateRingPlan;

pub const DmaArenaPlan = struct {
    base_address: u64,
    total_bytes: u64,
    enabled_device_slots: u8,
    dcbaa_address: u64,
    dcbaa_bytes: u32,
    scratchpad_array_address: u64,
    scratchpad_array_bytes: u64,
    scratchpad_buffers_address: u64,
    scratchpad_buffers_bytes: u64,
    device_contexts_address: u64,
    device_context_stride: u32,
    device_contexts_bytes: u64,
    enumeration_buffer_address: u64,
    enumeration_buffer_bytes: u32,
    input_context_address: u64,
    input_context_bytes: u32,
    control_transfer_rings_address: u64,
    control_transfer_ring_stride: u32,
    control_transfer_ring_trbs: u32,
    control_transfer_rings_bytes: u64,
    interrupt_transfer_rings_address: u64,
    interrupt_transfer_ring_stride: u32,
    interrupt_transfer_ring_trbs: u32,
    interrupt_transfer_rings_bytes: u64,
    interrupt_report_buffers_address: u64,
    interrupt_report_buffer_stride: u32,
    interrupt_report_buffers_bytes: u64,

    pub fn deviceContextAddress(self: DmaArenaPlan, slot_id: u8) Error!u64 {
        return self.slotAddress(self.device_contexts_address, self.device_context_stride, slot_id);
    }

    pub fn controlTransferRingAddress(self: DmaArenaPlan, slot_id: u8) Error!u64 {
        return self.slotAddress(self.control_transfer_rings_address, self.control_transfer_ring_stride, slot_id);
    }

    pub fn interruptTransferRingAddress(self: DmaArenaPlan, slot_id: u8) Error!u64 {
        return self.slotAddress(self.interrupt_transfer_rings_address, self.interrupt_transfer_ring_stride, slot_id);
    }

    pub fn interruptReportBufferAddress(self: DmaArenaPlan, slot_id: u8) Error!u64 {
        return self.slotAddress(self.interrupt_report_buffers_address, self.interrupt_report_buffer_stride, slot_id);
    }

    fn slotAddress(self: DmaArenaPlan, base: u64, stride: u32, slot_id: u8) Error!u64 {
        if (slot_id == 0 or slot_id > self.enabled_device_slots) return error.InvalidDeviceSlot;
        const offset = std.math.mul(u64, slot_id - 1, stride) catch return error.DmaLayoutOverflow;
        return std.math.add(u64, base, offset) catch return error.DmaLayoutOverflow;
    }
};

pub const ControllerDmaPlan = struct {
    base_address: u64,
    total_bytes: u64,
    ring_plan: RingPlan,
    event_ring_segment_table_address: u64,
    event_ring_segment_table_bytes: u32,
    event_ring_segment_table_entries: u32,
    arena: DmaArenaPlan,

    pub fn frameCount(self: ControllerDmaPlan) Error!u32 {
        if (self.total_bytes == 0 or self.total_bytes % XHCI_PAGE_BYTES != 0) {
            return error.DmaLayoutOverflow;
        }
        return std.math.cast(u32, self.total_bytes / XHCI_PAGE_BYTES) orelse
            error.DmaFrameCountOverflow;
    }
};

pub const DmaAccessRegion = struct {
    address: u64,
    bytes: u64,
    device_readable: bool,
    device_writable: bool,
};

pub fn planControllerDma(
    capabilities: CapabilityRegisters,
    enabled_device_slots: u8,
    base_address: u64,
) Error!ControllerDmaPlan {
    if (base_address == 0 or !aligned(base_address, XHCI_PAGE_BYTES)) {
        return error.DmaArenaBaseInvalid;
    }
    const event_ring_address = checkedAdd(base_address, XHCI_PAGE_BYTES) catch
        return error.DmaLayoutOverflow;
    return planControllerDmaFromRings(capabilities, enabled_device_slots, .{
        .command_ring_trbs = COMMAND_RING_TRBS,
        .event_ring_trbs = EVENT_RING_TRBS,
        .command_ring_address = base_address,
        .event_ring_address = event_ring_address,
    });
}

pub fn controllerDmaFrameCount(
    capabilities: CapabilityRegisters,
    enabled_device_slots: u8,
) Error!u32 {
    var maximum_frames: u32 = 0;
    var base_address = XHCI_PAGE_BYTES;
    while (base_address <= XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES) : (base_address += XHCI_PAGE_BYTES) {
        maximum_frames = @max(
            maximum_frames,
            try (try planControllerDma(
                capabilities,
                enabled_device_slots,
                base_address,
            )).frameCount(),
        );
    }
    return maximum_frames;
}

fn planControllerDmaFromRings(
    capabilities: CapabilityRegisters,
    enabled_device_slots: u8,
    ring_plan: RingPlan,
) Error!ControllerDmaPlan {
    try validateRingPlan(ring_plan);
    const event_ring_end = try ringEndAddress(
        ring_plan.event_ring_address,
        ring_plan.event_ring_trbs,
    );
    const event_ring_segment_table_address = alignForwardChecked(
        event_ring_end,
        ERST_TABLE_ALIGNMENT_BYTES,
    ) catch return error.DmaLayoutOverflow;
    const event_ring_segment_table_bytes = std.math.cast(
        u32,
        ERST_TABLE_ALIGNMENT_BYTES,
    ) orelse return error.DmaLayoutOverflow;
    const arena_start = checkedAdd(
        event_ring_segment_table_address,
        event_ring_segment_table_bytes,
    ) catch return error.DmaLayoutOverflow;
    const arena_base = alignForwardChecked(arena_start, XHCI_PAGE_BYTES) catch
        return error.DmaLayoutOverflow;
    const arena = try planDmaArena(capabilities, enabled_device_slots, arena_base);
    const plan_base = @min(ring_plan.command_ring_address, ring_plan.event_ring_address);
    const plan_end = checkedAdd(arena.base_address, arena.total_bytes) catch
        return error.DmaLayoutOverflow;
    if (plan_end <= plan_base) return error.DmaLayoutOverflow;
    return .{
        .base_address = plan_base,
        .total_bytes = plan_end - plan_base,
        .ring_plan = ring_plan,
        .event_ring_segment_table_address = event_ring_segment_table_address,
        .event_ring_segment_table_bytes = event_ring_segment_table_bytes,
        .event_ring_segment_table_entries = EVENT_RING_SEGMENT_TABLE_ENTRIES,
        .arena = arena,
    };
}

pub fn planDmaArena(
    capabilities: CapabilityRegisters,
    enabled_device_slots: u8,
    base_address: u64,
) Error!DmaArenaPlan {
    if (base_address == 0 or !aligned(base_address, XHCI_PAGE_BYTES)) {
        return error.DmaArenaBaseInvalid;
    }
    const slot_limit = @min(capabilities.max_device_slots, maxDeviceSlotsU8());
    if (enabled_device_slots == 0 or enabled_device_slots > slot_limit) {
        return error.DmaSlotCountInvalid;
    }

    const dcbaa_bytes: u32 = (@as(u32, enabled_device_slots) + 1) * DCBAA_ENTRY_BYTES;
    var cursor = checkedAdd(base_address, XHCI_PAGE_BYTES) catch return error.DmaLayoutOverflow;

    var scratchpad_array_address: u64 = 0;
    var scratchpad_array_bytes: u64 = 0;
    var scratchpad_buffers_address: u64 = 0;
    var scratchpad_buffers_bytes: u64 = 0;
    if (capabilities.max_scratchpad_buffers != 0) {
        scratchpad_array_address = cursor;
        scratchpad_array_bytes = std.math.mul(
            u64,
            capabilities.max_scratchpad_buffers,
            SCRATCHPAD_ARRAY_ENTRY_BYTES,
        ) catch return error.DmaLayoutOverflow;
        cursor = try advancePageRounded(cursor, scratchpad_array_bytes);

        scratchpad_buffers_address = cursor;
        scratchpad_buffers_bytes = std.math.mul(
            u64,
            capabilities.max_scratchpad_buffers,
            XHCI_PAGE_BYTES,
        ) catch return error.DmaLayoutOverflow;
        cursor = checkedAdd(cursor, scratchpad_buffers_bytes) catch return error.DmaLayoutOverflow;
    }

    const device_context_stride = std.math.mul(
        u32,
        DEVICE_CONTEXT_ENTRIES,
        capabilities.context_size.byteCount(),
    ) catch return error.DmaLayoutOverflow;
    const device_contexts_address = cursor;
    const device_contexts_bytes = std.math.mul(
        u64,
        enabled_device_slots,
        device_context_stride,
    ) catch return error.DmaLayoutOverflow;
    cursor = checkedAdd(cursor, device_contexts_bytes) catch return error.DmaLayoutOverflow;
    cursor = alignForwardChecked(cursor, XHCI_PAGE_BYTES) catch return error.DmaLayoutOverflow;

    cursor = alignForwardChecked(cursor, XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES) catch
        return error.DmaLayoutOverflow;
    const enumeration_buffer_address = cursor;
    const enumeration_buffer_bytes = USB_ENUMERATION_BUFFER_BYTES;
    cursor = checkedAdd(cursor, enumeration_buffer_bytes) catch return error.DmaLayoutOverflow;

    const input_context_address = cursor;
    const input_context_bytes = std.math.mul(
        u32,
        INPUT_CONTEXT_ENTRIES,
        capabilities.context_size.byteCount(),
    ) catch return error.DmaLayoutOverflow;
    cursor = checkedAdd(cursor, input_context_bytes) catch return error.DmaLayoutOverflow;
    cursor = alignForwardChecked(cursor, XHCI_PAGE_BYTES) catch return error.DmaLayoutOverflow;

    const control_transfer_ring_stride = std.math.mul(
        u32,
        TRANSFER_RING_TRBS,
        TRB_BYTES,
    ) catch return error.DmaLayoutOverflow;
    const control_transfer_rings_address = cursor;
    const control_transfer_rings_used_bytes = std.math.mul(
        u64,
        enabled_device_slots,
        control_transfer_ring_stride,
    ) catch return error.DmaLayoutOverflow;
    cursor = try advancePageRounded(cursor, control_transfer_rings_used_bytes);
    const control_transfer_rings_bytes = cursor - control_transfer_rings_address;

    const interrupt_transfer_ring_stride = control_transfer_ring_stride;
    const interrupt_transfer_rings_address = cursor;
    const interrupt_transfer_rings_used_bytes = std.math.mul(
        u64,
        enabled_device_slots,
        interrupt_transfer_ring_stride,
    ) catch return error.DmaLayoutOverflow;
    cursor = try advancePageRounded(cursor, interrupt_transfer_rings_used_bytes);
    const interrupt_transfer_rings_bytes = cursor - interrupt_transfer_rings_address;

    const interrupt_report_buffers_address = cursor;
    const interrupt_report_buffers_used_bytes = std.math.mul(
        u64,
        enabled_device_slots,
        INTERRUPT_REPORT_BUFFER_STRIDE,
    ) catch return error.DmaLayoutOverflow;
    cursor = try advancePageRounded(cursor, interrupt_report_buffers_used_bytes);
    const interrupt_report_buffers_bytes = cursor - interrupt_report_buffers_address;

    return .{
        .base_address = base_address,
        .total_bytes = cursor - base_address,
        .enabled_device_slots = enabled_device_slots,
        .dcbaa_address = base_address,
        .dcbaa_bytes = dcbaa_bytes,
        .scratchpad_array_address = scratchpad_array_address,
        .scratchpad_array_bytes = scratchpad_array_bytes,
        .scratchpad_buffers_address = scratchpad_buffers_address,
        .scratchpad_buffers_bytes = scratchpad_buffers_bytes,
        .device_contexts_address = device_contexts_address,
        .device_context_stride = device_context_stride,
        .device_contexts_bytes = device_contexts_bytes,
        .enumeration_buffer_address = enumeration_buffer_address,
        .enumeration_buffer_bytes = enumeration_buffer_bytes,
        .input_context_address = input_context_address,
        .input_context_bytes = input_context_bytes,
        .control_transfer_rings_address = control_transfer_rings_address,
        .control_transfer_ring_stride = control_transfer_ring_stride,
        .control_transfer_ring_trbs = TRANSFER_RING_TRBS,
        .control_transfer_rings_bytes = control_transfer_rings_bytes,
        .interrupt_transfer_rings_address = interrupt_transfer_rings_address,
        .interrupt_transfer_ring_stride = interrupt_transfer_ring_stride,
        .interrupt_transfer_ring_trbs = TRANSFER_RING_TRBS,
        .interrupt_transfer_rings_bytes = interrupt_transfer_rings_bytes,
        .interrupt_report_buffers_address = interrupt_report_buffers_address,
        .interrupt_report_buffer_stride = INTERRUPT_REPORT_BUFFER_STRIDE,
        .interrupt_report_buffers_bytes = interrupt_report_buffers_bytes,
    };
}

pub fn initializeControllerDma(
    plan: ControllerDmaPlan,
    memory: []u8,
) Error!void {
    const total_bytes = std.math.cast(usize, plan.total_bytes) orelse
        return error.DmaBufferTooSmall;
    if (memory.len < total_bytes) return error.DmaBufferTooSmall;
    @memset(memory[0..total_bytes], 0);

    try initializeLinkTrb(
        plan,
        memory,
        plan.ring_plan.command_ring_address,
        plan.ring_plan.command_ring_trbs,
    );
    var slot_id: u16 = 1;
    while (slot_id <= plan.arena.enabled_device_slots) : (slot_id += 1) {
        try initializeLinkTrb(
            plan,
            memory,
            try plan.arena.controlTransferRingAddress(@intCast(slot_id)),
            plan.arena.control_transfer_ring_trbs,
        );
        try initializeLinkTrb(
            plan,
            memory,
            try plan.arena.interruptTransferRingAddress(@intCast(slot_id)),
            plan.arena.interrupt_transfer_ring_trbs,
        );
    }

    const erst = try dmaBytes(
        plan,
        memory,
        plan.event_ring_segment_table_address,
        plan.event_ring_segment_table_bytes,
    );
    std.mem.writeInt(u64, erst[0..8], plan.ring_plan.event_ring_address, .little);
    std.mem.writeInt(u32, erst[8..12], plan.ring_plan.event_ring_trbs, .little);

    const dcbaa = try dmaBytes(
        plan,
        memory,
        plan.arena.dcbaa_address,
        plan.arena.dcbaa_bytes,
    );
    if (plan.arena.scratchpad_array_address != 0) {
        std.mem.writeInt(u64, dcbaa[0..8], plan.arena.scratchpad_array_address, .little);
        const scratchpad_array = try dmaBytes(
            plan,
            memory,
            plan.arena.scratchpad_array_address,
            plan.arena.scratchpad_array_bytes,
        );
        var index: u64 = 0;
        while (index < plan.arena.scratchpad_array_bytes / SCRATCHPAD_ARRAY_ENTRY_BYTES) : (index += 1) {
            const entry_offset: usize = @intCast(index * SCRATCHPAD_ARRAY_ENTRY_BYTES);
            const buffer_address = checkedAdd(
                plan.arena.scratchpad_buffers_address,
                index * XHCI_PAGE_BYTES,
            ) catch return error.DmaLayoutOverflow;
            std.mem.writeInt(u64, scratchpad_array[entry_offset..][0..8], buffer_address, .little);
        }
    }
}

pub fn resetTransferRing(
    plan: ControllerDmaPlan,
    memory: []u8,
    ring_address: u64,
    ring_trbs: u32,
) Error!void {
    try validateRing(ring_trbs, ring_address);
    const ring_bytes = std.math.mul(u64, ring_trbs, TRB_BYTES) catch
        return error.DmaLayoutOverflow;
    const ring = try dmaBytes(plan, memory, ring_address, ring_bytes);
    @memset(ring, 0);
    try initializeLinkTrb(plan, memory, ring_address, ring_trbs);
}

pub fn controllerDmaAccessRegions(
    plan: ControllerDmaPlan,
    storage: *[MAX_CONTROLLER_DMA_REGIONS]DmaAccessRegion,
) Error![]const DmaAccessRegion {
    const command_page_end = checkedAdd(plan.ring_plan.command_ring_address, XHCI_PAGE_BYTES) catch
        return error.DmaLayoutOverflow;
    const event_page_end = checkedAdd(plan.ring_plan.event_ring_address, XHCI_PAGE_BYTES) catch
        return error.DmaLayoutOverflow;
    const command_ring_end = try ringEndAddress(
        plan.ring_plan.command_ring_address,
        plan.ring_plan.command_ring_trbs,
    );
    const event_ring_end = try ringEndAddress(
        plan.ring_plan.event_ring_address,
        plan.ring_plan.event_ring_trbs,
    );
    const erst_end = checkedAdd(
        plan.event_ring_segment_table_address,
        plan.event_ring_segment_table_bytes,
    ) catch return error.DmaLayoutOverflow;
    const plan_end = checkedAdd(plan.base_address, plan.total_bytes) catch
        return error.DmaLayoutOverflow;
    const control_transfer_rings_end = checkedAdd(
        plan.arena.control_transfer_rings_address,
        plan.arena.control_transfer_rings_bytes,
    ) catch return error.DmaLayoutOverflow;
    const interrupt_transfer_rings_end = checkedAdd(
        plan.arena.interrupt_transfer_rings_address,
        plan.arena.interrupt_transfer_rings_bytes,
    ) catch return error.DmaLayoutOverflow;
    const interrupt_report_buffers_end = checkedAdd(
        plan.arena.interrupt_report_buffers_address,
        plan.arena.interrupt_report_buffers_bytes,
    ) catch return error.DmaLayoutOverflow;
    if (plan.ring_plan.command_ring_address != plan.base_address or
        !aligned(plan.ring_plan.command_ring_address, XHCI_PAGE_BYTES) or
        !aligned(plan.ring_plan.event_ring_address, XHCI_PAGE_BYTES) or
        command_ring_end > command_page_end or
        event_ring_end > event_page_end or
        plan.event_ring_segment_table_address < event_ring_end or
        erst_end > event_page_end or
        !aligned(plan.arena.control_transfer_rings_address, XHCI_PAGE_BYTES) or
        control_transfer_rings_end != plan.arena.interrupt_transfer_rings_address or
        !aligned(plan.arena.interrupt_transfer_rings_address, XHCI_PAGE_BYTES) or
        interrupt_transfer_rings_end != plan.arena.interrupt_report_buffers_address or
        !aligned(plan.arena.interrupt_report_buffers_address, XHCI_PAGE_BYTES) or
        interrupt_report_buffers_end != plan_end)
    {
        return error.DmaAddressOutsidePlan;
    }

    var count: usize = 0;
    storage[count] = .{
        .address = plan.ring_plan.command_ring_address,
        .bytes = XHCI_PAGE_BYTES,
        .device_readable = true,
        .device_writable = false,
    };
    count += 1;
    storage[count] = .{
        .address = plan.ring_plan.event_ring_address,
        .bytes = XHCI_PAGE_BYTES,
        .device_readable = true,
        .device_writable = true,
    };
    count += 1;
    storage[count] = .{
        .address = plan.arena.dcbaa_address,
        .bytes = XHCI_PAGE_BYTES,
        .device_readable = true,
        .device_writable = false,
    };
    count += 1;
    if (plan.arena.scratchpad_array_address != 0) {
        if (plan.arena.scratchpad_buffers_address <= plan.arena.scratchpad_array_address) {
            return error.DmaAddressOutsidePlan;
        }
        storage[count] = .{
            .address = plan.arena.scratchpad_array_address,
            .bytes = plan.arena.scratchpad_buffers_address - plan.arena.scratchpad_array_address,
            .device_readable = true,
            .device_writable = false,
        };
        count += 1;
        storage[count] = .{
            .address = plan.arena.scratchpad_buffers_address,
            .bytes = plan.arena.scratchpad_buffers_bytes,
            .device_readable = true,
            .device_writable = true,
        };
        count += 1;
    }
    const enumeration_buffer_end = checkedAdd(
        plan.arena.enumeration_buffer_address,
        plan.arena.enumeration_buffer_bytes,
    ) catch return error.DmaLayoutOverflow;
    if (plan.arena.enumeration_buffer_address <= plan.arena.device_contexts_address or
        enumeration_buffer_end != plan.arena.input_context_address)
    {
        return error.DmaAddressOutsidePlan;
    }
    storage[count] = .{
        .address = plan.arena.device_contexts_address,
        .bytes = plan.arena.input_context_address - plan.arena.device_contexts_address,
        .device_readable = true,
        .device_writable = true,
    };
    count += 1;
    storage[count] = .{
        .address = plan.arena.input_context_address,
        .bytes = plan.arena.interrupt_report_buffers_address -
            plan.arena.input_context_address,
        .device_readable = true,
        .device_writable = false,
    };
    count += 1;
    storage[count] = .{
        .address = plan.arena.interrupt_report_buffers_address,
        .bytes = plan.arena.interrupt_report_buffers_bytes,
        .device_readable = false,
        .device_writable = true,
    };
    count += 1;

    for (storage[0..count]) |region| {
        const region_end = checkedAdd(region.address, region.bytes) catch
            return error.DmaLayoutOverflow;
        if (!aligned(region.address, XHCI_PAGE_BYTES) or
            region.bytes == 0 or region.bytes % XHCI_PAGE_BYTES != 0 or
            region.address < plan.base_address or region_end > plan_end)
        {
            return error.DmaAddressOutsidePlan;
        }
    }
    return storage[0..count];
}

fn initializeLinkTrb(
    plan: ControllerDmaPlan,
    memory: []u8,
    ring_address: u64,
    ring_trbs: u32,
) Error!void {
    if (ring_trbs < 2) return error.RingTooSmall;
    const ring_bytes = std.math.mul(u64, ring_trbs, TRB_BYTES) catch
        return error.DmaLayoutOverflow;
    const link_address = checkedAdd(ring_address, ring_bytes - TRB_BYTES) catch
        return error.DmaLayoutOverflow;
    const link = try dmaBytes(plan, memory, link_address, TRB_BYTES);
    std.mem.writeInt(u64, link[0..8], ring_address, .little);
    std.mem.writeInt(u32, link[12..16], ringLinkControl(@intCast(COMMAND_RING_INITIAL_CYCLE_STATE)), .little);
}

fn dmaBytes(
    plan: ControllerDmaPlan,
    memory: []u8,
    address: u64,
    byte_count: u64,
) Error![]u8 {
    if (address < plan.base_address) return error.DmaAddressOutsidePlan;
    const offset = address - plan.base_address;
    const end = checkedAdd(offset, byte_count) catch return error.DmaLayoutOverflow;
    if (end > plan.total_bytes or end > memory.len) return error.DmaAddressOutsidePlan;
    const start_index = std.math.cast(usize, offset) orelse return error.DmaAddressOutsidePlan;
    const end_index = std.math.cast(usize, end) orelse return error.DmaAddressOutsidePlan;
    return memory[start_index..end_index];
}

fn checkedAdd(left: u64, right: u64) error{Overflow}!u64 {
    return std.math.add(u64, left, right) catch error.Overflow;
}

fn alignForwardChecked(address: u64, alignment: u64) error{Overflow}!u64 {
    if (alignment == 0) return address;
    const remainder = address % alignment;
    return if (remainder == 0)
        address
    else
        checkedAdd(address, alignment - remainder);
}

fn advancePageRounded(address: u64, bytes: u64) Error!u64 {
    const end = checkedAdd(address, bytes) catch return error.DmaLayoutOverflow;
    return alignForwardChecked(end, XHCI_PAGE_BYTES) catch error.DmaLayoutOverflow;
}

test "xHCI DMA arena packs complete contexts and scratchpads without overlap" {
    const capabilities = defaultCapabilityRegisters();
    const plan = try planDmaArena(capabilities, TEST_MAX_DEVICE_SLOTS, 0x4000);
    try std.testing.expectEqual(@as(u64, 0x4000), plan.dcbaa_address);
    try std.testing.expectEqual(@as(u32, 33 * DCBAA_ENTRY_BYTES), plan.dcbaa_bytes);
    try std.testing.expectEqual(@as(u64, 0x5000), plan.scratchpad_array_address);
    try std.testing.expectEqual(@as(u64, 33 * SCRATCHPAD_ARRAY_ENTRY_BYTES), plan.scratchpad_array_bytes);
    try std.testing.expectEqual(@as(u64, 0x6000), plan.scratchpad_buffers_address);
    try std.testing.expectEqual(@as(u64, 33) * XHCI_PAGE_BYTES, plan.scratchpad_buffers_bytes);
    try std.testing.expectEqual(@as(u32, 2048), plan.device_context_stride);
    try std.testing.expectEqual(@as(u64, 0x27000), plan.device_contexts_address);
    try std.testing.expectEqual(@as(u64, 0x10000), plan.device_contexts_bytes);
    try std.testing.expectEqual(@as(u64, 0x27000), try plan.deviceContextAddress(1));
    try std.testing.expectEqual(@as(u64, 0x36800), try plan.deviceContextAddress(32));
    try std.testing.expectError(error.InvalidDeviceSlot, plan.deviceContextAddress(0));
    try std.testing.expectError(error.InvalidDeviceSlot, plan.deviceContextAddress(33));
    try std.testing.expectEqual(@as(u64, 0x40000), plan.enumeration_buffer_address);
    try std.testing.expectEqual(USB_ENUMERATION_BUFFER_BYTES, plan.enumeration_buffer_bytes);
    try std.testing.expectEqual(@as(u64, 0x50000), plan.input_context_address);
    try std.testing.expectEqual(@as(u32, 2112), plan.input_context_bytes);
    try std.testing.expectEqual(@as(u64, 0x51000), plan.control_transfer_rings_address);
    try std.testing.expectEqual(@as(u32, 256), plan.control_transfer_ring_stride);
    try std.testing.expectEqual(@as(u64, 0x2000), plan.control_transfer_rings_bytes);
    try std.testing.expectEqual(@as(u64, 0x51000), try plan.controlTransferRingAddress(1));
    try std.testing.expectEqual(@as(u64, 0x52F00), try plan.controlTransferRingAddress(32));
    try std.testing.expectError(error.InvalidDeviceSlot, plan.controlTransferRingAddress(33));
    try std.testing.expectEqual(@as(u64, 0x53000), plan.interrupt_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x2000), plan.interrupt_transfer_rings_bytes);
    try std.testing.expectEqual(@as(u64, 0x53000), try plan.interruptTransferRingAddress(1));
    try std.testing.expectEqual(@as(u64, 0x54F00), try plan.interruptTransferRingAddress(32));
    try std.testing.expectEqual(@as(u64, 0x55000), plan.interrupt_report_buffers_address);
    try std.testing.expectEqual(@as(u64, 0x55000), try plan.interruptReportBufferAddress(1));
    try std.testing.expectEqual(@as(u64, 0x557C0), try plan.interruptReportBufferAddress(32));
    try std.testing.expectError(error.InvalidDeviceSlot, plan.interruptReportBufferAddress(33));
    try std.testing.expectEqual(@as(u64, 0x52000), plan.total_bytes);
}

test "xHCI DMA arena handles compact contexts and rejects invalid ranges" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.context_size = .bytes_32;
    capabilities.max_device_slots = 3;
    capabilities.max_scratchpad_buffers = 0;
    capabilities.scratchpad_restore = false;
    const plan = try planDmaArena(capabilities, 3, 0x1000);
    try std.testing.expectEqual(@as(u64, 0), plan.scratchpad_array_address);
    try std.testing.expectEqual(@as(u64, 0), plan.scratchpad_buffers_address);
    try std.testing.expectEqual(@as(u32, 1024), plan.device_context_stride);
    try std.testing.expectEqual(@as(u64, 0x2000), plan.device_contexts_address);
    try std.testing.expectEqual(@as(u64, 3072), plan.device_contexts_bytes);
    try std.testing.expectEqual(@as(u64, 0x10000), plan.enumeration_buffer_address);
    try std.testing.expectEqual(@as(u64, 0x20000), plan.input_context_address);
    try std.testing.expectEqual(@as(u32, 1056), plan.input_context_bytes);
    try std.testing.expectEqual(@as(u64, 0x21000), plan.control_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, XHCI_PAGE_BYTES), plan.control_transfer_rings_bytes);
    try std.testing.expectEqual(@as(u64, 0x22000), plan.interrupt_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x23000), plan.interrupt_report_buffers_address);
    try std.testing.expectEqual(@as(u64, 0x23000), plan.total_bytes);

    try std.testing.expectError(error.DmaArenaBaseInvalid, planDmaArena(capabilities, 3, 0));
    try std.testing.expectError(error.DmaArenaBaseInvalid, planDmaArena(capabilities, 3, 0x1800));
    try std.testing.expectError(error.DmaSlotCountInvalid, planDmaArena(capabilities, 0, 0x1000));
    try std.testing.expectError(error.DmaSlotCountInvalid, planDmaArena(capabilities, 4, 0x1000));
    const final_page = std.math.maxInt(u64) & ~(XHCI_PAGE_BYTES - 1);
    try std.testing.expectError(error.DmaLayoutOverflow, planDmaArena(capabilities, 1, final_page));
}

test "xHCI DMA arena page-rounds the maximum scratchpad pointer array" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_scratchpad_buffers = 1023;
    const plan = try planDmaArena(capabilities, 1, 0x1000);
    try std.testing.expectEqual(@as(u64, 0x2000), plan.scratchpad_array_address);
    try std.testing.expectEqual(@as(u64, 8184), plan.scratchpad_array_bytes);
    try std.testing.expectEqual(@as(u64, 0x4000), plan.scratchpad_buffers_address);
    try std.testing.expectEqual(@as(u64, 1023) * XHCI_PAGE_BYTES, plan.scratchpad_buffers_bytes);
    try std.testing.expectEqual(@as(u64, 0x403000), plan.device_contexts_address);
    try std.testing.expectEqual(@as(u64, 0x410000), plan.enumeration_buffer_address);
    try std.testing.expectEqual(@as(u64, 0x420000), plan.input_context_address);
    try std.testing.expectEqual(@as(u64, 0x421000), plan.control_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x422000), plan.interrupt_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x423000), plan.interrupt_report_buffers_address);
    try std.testing.expectEqual(@as(u64, 0x423000), plan.total_bytes);

    capabilities.max_device_slots = TEST_MAX_DEVICE_SLOTS;
    const full_plan = try planControllerDma(capabilities, TEST_MAX_DEVICE_SLOTS, 0x1000);
    try std.testing.expectEqual(@as(u32, 1077), try full_plan.frameCount());
}

test "xHCI controller DMA plan initializes rings tables and scratchpad pointers" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_scratchpad_buffers = 2;
    const plan = try planControllerDma(capabilities, 1, 0x1000);
    try std.testing.expectEqual(@as(u32, 35), try plan.frameCount());
    const reserved_frames = try controllerDmaFrameCount(capabilities, 1);
    var saw_worst_case = false;
    var candidate_base = XHCI_PAGE_BYTES;
    while (candidate_base <= XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES) : (candidate_base += XHCI_PAGE_BYTES) {
        const candidate_frames = try (try planControllerDma(
            capabilities,
            1,
            candidate_base,
        )).frameCount();
        try std.testing.expect(candidate_frames <= reserved_frames);
        saw_worst_case = saw_worst_case or candidate_frames == reserved_frames;
    }
    try std.testing.expect(saw_worst_case);
    try std.testing.expectEqual(@as(u64, 0x21000), plan.arena.control_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x2400), plan.event_ring_segment_table_address);
    try std.testing.expectEqual(@as(u32, 64), plan.event_ring_segment_table_bytes);
    try std.testing.expectEqual(@as(u64, 0x3000), plan.arena.base_address);

    var memory = @as([35 * @as(usize, XHCI_PAGE_BYTES)]u8, @splat(0xA5));
    try std.testing.expectError(
        error.DmaBufferTooSmall,
        initializeControllerDma(plan, memory[0 .. memory.len - 1]),
    );
    try initializeControllerDma(plan, &memory);

    const command_link = memory[(COMMAND_RING_TRBS - 1) * TRB_BYTES ..][0..TRB_BYTES];
    try std.testing.expectEqual(@as(u64, 0x1000), std.mem.readInt(u64, command_link[0..8], .little));
    try std.testing.expectEqual(
        (@as(u32, LINK_TRB_TYPE) << TRB_TYPE_SHIFT) | LINK_TRB_TOGGLE_CYCLE | 1,
        std.mem.readInt(u32, command_link[12..16], .little),
    );
    const transfer_link_offset: usize = @intCast(
        plan.arena.control_transfer_rings_address - plan.base_address +
            (@as(u64, plan.arena.control_transfer_ring_trbs) - 1) * TRB_BYTES,
    );
    try std.testing.expectEqual(
        plan.arena.control_transfer_rings_address,
        std.mem.readInt(u64, memory[transfer_link_offset..][0..8], .little),
    );
    const interrupt_link_offset: usize = @intCast(
        plan.arena.interrupt_transfer_rings_address - plan.base_address +
            (@as(u64, plan.arena.interrupt_transfer_ring_trbs) - 1) * TRB_BYTES,
    );
    try std.testing.expectEqual(
        plan.arena.interrupt_transfer_rings_address,
        std.mem.readInt(u64, memory[interrupt_link_offset..][0..8], .little),
    );
    const erst_offset: usize = @intCast(plan.event_ring_segment_table_address - plan.base_address);
    try std.testing.expectEqual(
        plan.ring_plan.event_ring_address,
        std.mem.readInt(u64, memory[erst_offset..][0..8], .little),
    );
    try std.testing.expectEqual(
        plan.ring_plan.event_ring_trbs,
        std.mem.readInt(u32, memory[erst_offset + 8 ..][0..4], .little),
    );
    const dcbaa_offset: usize = @intCast(plan.arena.dcbaa_address - plan.base_address);
    try std.testing.expectEqual(
        plan.arena.scratchpad_array_address,
        std.mem.readInt(u64, memory[dcbaa_offset..][0..8], .little),
    );
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, memory[dcbaa_offset + 8 ..][0..8], .little));
    const scratchpad_offset: usize = @intCast(
        plan.arena.scratchpad_array_address - plan.base_address,
    );
    try std.testing.expectEqual(
        plan.arena.scratchpad_buffers_address,
        std.mem.readInt(u64, memory[scratchpad_offset..][0..8], .little),
    );
    try std.testing.expectEqual(
        plan.arena.scratchpad_buffers_address + XHCI_PAGE_BYTES,
        std.mem.readInt(u64, memory[scratchpad_offset + 8 ..][0..8], .little),
    );
}

test "xHCI transfer ring reset discards stale slot TRBs before reuse" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_scratchpad_buffers = 2;
    const plan = try planControllerDma(capabilities, 1, 0x1000);
    var memory = @as([35 * @as(usize, XHCI_PAGE_BYTES)]u8, @splat(0));
    const ring_address = plan.arena.interrupt_transfer_rings_address;
    const ring_offset: usize = @intCast(ring_address - plan.base_address);
    const ring_bytes: usize = plan.arena.interrupt_transfer_ring_stride;
    @memset(memory[ring_offset..][0..ring_bytes], 0xA5);

    try resetTransferRing(
        plan,
        &memory,
        ring_address,
        plan.arena.interrupt_transfer_ring_trbs,
    );
    try std.testing.expectEqualSlices(
        u8,
        &(@as([TRB_BYTES]u8, @splat(0))),
        memory[ring_offset..][0..TRB_BYTES],
    );
    const link_offset = ring_offset + ring_bytes - TRB_BYTES;
    try std.testing.expectEqual(ring_address, std.mem.readInt(u64, memory[link_offset..][0..8], .little));
    try std.testing.expectEqual(
        ringLinkControl(1),
        std.mem.readInt(u32, memory[link_offset + 12 ..][0..4], .little),
    );
}

test "xHCI controller DMA regions preserve page-granular direction isolation" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_scratchpad_buffers = 2;
    const plan = try planControllerDma(capabilities, 1, 0x1000);
    var region_storage: [MAX_CONTROLLER_DMA_REGIONS]DmaAccessRegion = undefined;
    const regions = try controllerDmaAccessRegions(plan, &region_storage);
    try std.testing.expectEqual(@as(usize, 8), regions.len);
    try std.testing.expectEqualDeep(DmaAccessRegion{
        .address = 0x1000,
        .bytes = XHCI_PAGE_BYTES,
        .device_readable = true,
        .device_writable = false,
    }, regions[0]);
    try std.testing.expect(regions[1].device_readable and regions[1].device_writable);
    try std.testing.expectEqual(plan.arena.dcbaa_address, regions[2].address);
    try std.testing.expect(regions[3].device_readable and !regions[3].device_writable);
    try std.testing.expectEqual(plan.arena.scratchpad_buffers_bytes, regions[4].bytes);
    try std.testing.expect(regions[4].device_readable and regions[4].device_writable);
    try std.testing.expect(regions[5].device_readable and regions[5].device_writable);
    try std.testing.expect(regions[6].device_readable and !regions[6].device_writable);
    try std.testing.expect(!regions[7].device_readable and regions[7].device_writable);
    try std.testing.expectEqual(
        plan.arena.interrupt_report_buffers_address,
        regions[7].address,
    );

    capabilities.context_size = .bytes_32;
    capabilities.max_device_slots = 3;
    capabilities.max_scratchpad_buffers = 0;
    capabilities.scratchpad_restore = false;
    const compact = try planControllerDma(capabilities, 3, 0x1000);
    try std.testing.expectEqual(@as(u32, 35), try compact.frameCount());
    const compact_regions = try controllerDmaAccessRegions(compact, &region_storage);
    try std.testing.expectEqual(@as(usize, 6), compact_regions.len);
    try std.testing.expectEqual(@as(u64, 0x1C000), compact_regions[3].bytes);
    try std.testing.expectEqual(@as(u64, 0x3000), compact_regions[4].bytes);
    try std.testing.expectEqual(@as(u64, XHCI_PAGE_BYTES), compact_regions[5].bytes);
}
