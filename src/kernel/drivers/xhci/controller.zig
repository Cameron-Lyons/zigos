//! xHCI operational and runtime registers: controller reset, start and
//! quiesce, event-ring acknowledgement, DMA register programming, port
//! status and doorbells.

const std = @import("std");
const endian = @import("../../utils/endian.zig");
const spin = @import("../../utils/spin.zig");
const xhci = @import("../xhci.zig");

const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

const COMMAND_RING_INITIAL_CYCLE_STATE = xhci.trb.COMMAND_RING_INITIAL_CYCLE_STATE;
const CONTROLLER_HALT_TIMEOUT_MILLISECONDS = xhci.CONTROLLER_HALT_TIMEOUT_MILLISECONDS;
const CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS = xhci.CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS;
const CapabilityRegisters = xhci.CapabilityRegisters;
const ControllerDmaPlan = xhci.dma_plan.ControllerDmaPlan;
const DOORBELL_OFFSET_ALIGNMENT_MASK = xhci.DOORBELL_OFFSET_ALIGNMENT_MASK;
const EVENT_RING_SEGMENT_TABLE_ENTRIES = xhci.EVENT_RING_SEGMENT_TABLE_ENTRIES;
const Error = xhci.Error;
const PortProtocol = xhci.PortProtocol;
const RING_ALIGNMENT_BYTES = xhci.RING_ALIGNMENT_BYTES;
const TEST_CAPABILITY_LENGTH = xhci.TEST_CAPABILITY_LENGTH;
const TEST_MAX_DEVICE_SLOTS = xhci.TEST_MAX_DEVICE_SLOTS;
const defaultCapabilityRegisters = xhci.defaultCapabilityRegisters;
const maxDeviceSlotsU8 = xhci.maxDeviceSlotsU8;
const planControllerDma = xhci.dma_plan.planControllerDma;

const OPERATIONAL_USB_COMMAND_OFFSET: u32 = 0x00;
const OPERATIONAL_USB_STATUS_OFFSET: u32 = 0x04;
const OPERATIONAL_PAGE_SIZE_OFFSET: u32 = 0x08;
const OPERATIONAL_COMMAND_RING_CONTROL_OFFSET: u32 = 0x18;
const OPERATIONAL_DEVICE_CONTEXT_BASE_ARRAY_POINTER_OFFSET: u32 = 0x30;
const OPERATIONAL_CONFIGURE_OFFSET: u32 = 0x38;
const OPERATIONAL_PORT_REGISTER_BASE_OFFSET: u32 = 0x400;
const OPERATIONAL_PORT_REGISTER_STRIDE: u32 = 0x10;
const USB_COMMAND_RUN_STOP: u32 = 1 << 0;
const USB_COMMAND_HOST_CONTROLLER_RESET: u32 = 1 << 1;
const USB_COMMAND_INTERRUPTER_ENABLE: u32 = 1 << 2;
const USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE: u32 = 1 << 3;
const USB_STATUS_HOST_CONTROLLER_HALTED: u32 = 1 << 0;
const USB_STATUS_HOST_SYSTEM_ERROR: u32 = 1 << 2;
const USB_STATUS_CONTROLLER_NOT_READY: u32 = 1 << 11;
const USB_STATUS_HOST_CONTROLLER_ERROR: u32 = 1 << 12;
const PAGE_SIZE_4K_SUPPORTED: u32 = 1 << 0;
const COMMAND_RING_RUNNING: u64 = 1 << 3;
const PRIMARY_INTERRUPTER_OFFSET: u32 = 0x20;
const INTERRUPTER_MANAGEMENT_OFFSET: u32 = 0x00;
const INTERRUPTER_MODERATION_OFFSET: u32 = 0x04;
const EVENT_RING_SEGMENT_TABLE_SIZE_OFFSET: u32 = 0x08;
const EVENT_RING_SEGMENT_TABLE_BASE_OFFSET: u32 = 0x10;
const EVENT_RING_DEQUEUE_POINTER_OFFSET: u32 = 0x18;
const INTERRUPTER_PENDING: u32 = 1 << 0;
const INTERRUPTER_ENABLE: u32 = 1 << 1;
const EVENT_HANDLER_BUSY: u64 = 1 << 3;
const INTERRUPTER_MODERATION_INTERVAL_125_MICROSECONDS: u32 = 500;
const ADDRESS_64_BYTE_ALIGNMENT_MASK: u64 = RING_ALIGNMENT_BYTES - 1;
const EVENT_RING_DEQUEUE_POINTER_MASK: u64 = ~@as(u64, 0xF);
const PORT_CURRENT_CONNECT_STATUS: u32 = 1 << 0;
const PORT_ENABLED_DISABLED: u32 = 1 << 1;
const PORT_OVER_CURRENT_ACTIVE: u32 = 1 << 3;
const PORT_RESET: u32 = 1 << 4;
const PORT_LINK_STATE_SHIFT: u5 = 5;
const PORT_LINK_STATE_MASK: u32 = 0xF;
const PORT_POWER: u32 = 1 << 9;
const PORT_SPEED_SHIFT: u5 = 10;
const PORT_SPEED_MASK: u32 = 0xF;
const PORT_COLD_ATTACH_STATUS: u32 = 1 << 24;
const PORT_WAKE_ENABLE_MASK: u32 = 0x7 << 25;
const PORT_INDICATOR_CONTROL_MASK: u32 = 0x3 << 14;
const PORT_CHANGE_MASK: u32 = 0x7F << 17;
const PORT_READ_WRITE_STICKY_MASK: u32 =
    (PORT_LINK_STATE_MASK << PORT_LINK_STATE_SHIFT) |
    PORT_POWER |
    PORT_INDICATOR_CONTROL_MASK |
    PORT_WAKE_ENABLE_MASK;
const CONFIG_MAX_DEVICE_SLOTS_ENABLED_MASK: u32 = 0xFF;
pub const PortStatus = struct {
    connected: bool,
    enabled: bool,
    over_current: bool,
    reset_active: bool,
    link_state: u4,
    powered: bool,
    speed: u4,
    cold_attach: bool,
    change_bits: u7,
};

pub fn decodePortStatus(value: u32) PortStatus {
    return .{
        .connected = (value & PORT_CURRENT_CONNECT_STATUS) != 0,
        .enabled = (value & PORT_ENABLED_DISABLED) != 0,
        .over_current = (value & PORT_OVER_CURRENT_ACTIVE) != 0,
        .reset_active = (value & PORT_RESET) != 0,
        .link_state = @truncate((value >> PORT_LINK_STATE_SHIFT) & PORT_LINK_STATE_MASK),
        .powered = (value & PORT_POWER) != 0,
        .speed = @truncate((value >> PORT_SPEED_SHIFT) & PORT_SPEED_MASK),
        .cold_attach = (value & PORT_COLD_ATTACH_STATUS) != 0,
        .change_bits = @truncate((value & PORT_CHANGE_MASK) >> 17),
    };
}

pub fn portStatusAcknowledge(value: u32) u32 {
    return (value & PORT_READ_WRITE_STICKY_MASK) | (value & PORT_CHANGE_MASK);
}

pub fn portResetWrite(value: u32, protocol: PortProtocol) u32 {
    return portStatusAcknowledge(value) |
        (if (protocol.kind == .usb2) PORT_RESET else @as(u32, 1) << 31);
}

pub fn portRegisterOffset(capabilities: CapabilityRegisters, port_id: u8) Error!u32 {
    if (port_id == 0 or port_id > capabilities.max_ports) return error.InvalidPort;
    const relative = std.math.mul(
        u32,
        @as(u32, port_id - 1),
        OPERATIONAL_PORT_REGISTER_STRIDE,
    ) catch return error.InvalidPort;
    return std.math.add(
        u32,
        @as(u32, capabilities.capability_length) + OPERATIONAL_PORT_REGISTER_BASE_OFFSET,
        relative,
    ) catch return error.InvalidPort;
}

pub fn ringCommandDoorbell(capabilities: CapabilityRegisters, mmio: anytype) Error!void {
    if (capabilities.doorbell_offset == 0) return error.MissingDoorbellRegisters;
    if ((capabilities.doorbell_offset & DOORBELL_OFFSET_ALIGNMENT_MASK) != 0) {
        return error.InvalidDoorbellOffset;
    }
    mmio.writeReg32(capabilities.doorbell_offset, 0);
}

pub fn ringDeviceDoorbell(
    capabilities: CapabilityRegisters,
    slot_id: u8,
    endpoint_id: u5,
    mmio: anytype,
) Error!void {
    if (capabilities.doorbell_offset == 0) return error.MissingDoorbellRegisters;
    if ((capabilities.doorbell_offset & DOORBELL_OFFSET_ALIGNMENT_MASK) != 0) {
        return error.InvalidDoorbellOffset;
    }
    if (slot_id == 0 or slot_id > capabilities.max_device_slots or
        slot_id > maxDeviceSlotsU8())
    {
        return error.InvalidDeviceSlot;
    }
    if (endpoint_id == 0) return error.EndpointMismatch;
    const slot_offset = std.math.mul(u32, slot_id, @sizeOf(u32)) catch
        return error.InvalidDoorbellOffset;
    const offset = std.math.add(u32, capabilities.doorbell_offset, slot_offset) catch
        return error.InvalidDoorbellOffset;
    mmio.writeReg32(offset, endpoint_id);
}

pub fn resetOwnedController(
    capability_length: u8,
    mmio: anytype,
    clock: anytype,
) Error!void {
    const operational_base: u32 = capability_length;
    const command_offset = operational_base + OPERATIONAL_USB_COMMAND_OFFSET;
    const status_offset = operational_base + OPERATIONAL_USB_STATUS_OFFSET;

    var initial_ready_deadline = clock.afterMilliseconds(CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS);
    var status = mmio.readReg32(status_offset);
    while ((status & USB_STATUS_CONTROLLER_NOT_READY) != 0) {
        if (initial_ready_deadline.expired()) return error.ControllerNotReadyTimeout;
        spin.hint();
        status = mmio.readReg32(status_offset);
    }

    const quiesce_mask = USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE |
        USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE;
    if ((status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0) {
        var halt_deadline = clock.afterMilliseconds(CONTROLLER_HALT_TIMEOUT_MILLISECONDS);
        const command = mmio.readReg32(command_offset);
        mmio.writeReg32(command_offset, command & ~quiesce_mask);
        status = mmio.readReg32(status_offset);
        while ((status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0) {
            if (halt_deadline.expired()) return error.ControllerHaltTimeout;
            spin.hint();
            status = mmio.readReg32(status_offset);
        }
    }

    var reset_deadline = clock.afterMilliseconds(CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS);
    const command = mmio.readReg32(command_offset);
    mmio.writeReg32(
        command_offset,
        (command & ~quiesce_mask) | USB_COMMAND_HOST_CONTROLLER_RESET,
    );
    var reset_command = mmio.readReg32(command_offset);
    while ((reset_command & USB_COMMAND_HOST_CONTROLLER_RESET) != 0) {
        if (reset_deadline.expired()) return error.ControllerResetTimeout;
        spin.hint();
        reset_command = mmio.readReg32(command_offset);
    }

    var post_reset_ready_deadline = clock.afterMilliseconds(CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS);
    status = mmio.readReg32(status_offset);
    while ((status & USB_STATUS_CONTROLLER_NOT_READY) != 0) {
        if (post_reset_ready_deadline.expired()) return error.ControllerNotReadyTimeout;
        spin.hint();
        status = mmio.readReg32(status_offset);
    }
    if ((status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0 or
        (status & USB_STATUS_HOST_CONTROLLER_ERROR) != 0)
    {
        return error.ControllerResetFailed;
    }
}

pub fn startOwnedController(
    capabilities: CapabilityRegisters,
    mmio: anytype,
    clock: anytype,
) Error!void {
    const operational_base: u32 = capabilities.capability_length;
    const command_offset = operational_base + OPERATIONAL_USB_COMMAND_OFFSET;
    const status_offset = operational_base + OPERATIONAL_USB_STATUS_OFFSET;
    const fatal_status = USB_STATUS_HOST_SYSTEM_ERROR | USB_STATUS_HOST_CONTROLLER_ERROR;
    const initial_status = mmio.readReg32(status_offset);
    if ((initial_status & (USB_STATUS_CONTROLLER_NOT_READY | fatal_status)) != 0 or
        (initial_status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0)
    {
        return error.ControllerStartUnavailable;
    }
    errdefer quiesceOwnedController(capabilities, mmio);

    const primary_interrupter = std.math.add(
        u32,
        capabilities.runtime_register_offset,
        PRIMARY_INTERRUPTER_OFFSET,
    ) catch return error.DmaLayoutOverflow;
    const iman_offset = primary_interrupter + INTERRUPTER_MANAGEMENT_OFFSET;
    const iman = mmio.readReg32(iman_offset);
    mmio.writeReg32(
        iman_offset,
        (iman & ~INTERRUPTER_PENDING) | INTERRUPTER_ENABLE,
    );
    if ((mmio.readReg32(iman_offset) & INTERRUPTER_ENABLE) == 0) {
        return error.ControllerStartFailed;
    }

    const enable_mask = USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE |
        USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE;
    const command = mmio.readReg32(command_offset);
    mmio.writeReg32(command_offset, command | enable_mask);

    var deadline = clock.afterMilliseconds(CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS);
    var status = mmio.readReg32(status_offset);
    while ((status & USB_STATUS_HOST_CONTROLLER_HALTED) != 0) {
        if ((status & (USB_STATUS_CONTROLLER_NOT_READY | fatal_status)) != 0) {
            return error.ControllerStartFailed;
        }
        if (deadline.expired()) return error.ControllerStartTimeout;
        spin.hint();
        status = mmio.readReg32(status_offset);
    }
    if ((status & (USB_STATUS_CONTROLLER_NOT_READY | fatal_status)) != 0 or
        (mmio.readReg32(command_offset) & enable_mask) != enable_mask)
    {
        return error.ControllerStartFailed;
    }
}

pub fn quiesceOwnedController(
    capabilities: CapabilityRegisters,
    mmio: anytype,
) void {
    const primary_interrupter = capabilities.runtime_register_offset + PRIMARY_INTERRUPTER_OFFSET;
    const iman_offset = primary_interrupter + INTERRUPTER_MANAGEMENT_OFFSET;
    const iman = mmio.readReg32(iman_offset);
    mmio.writeReg32(
        iman_offset,
        iman & ~(INTERRUPTER_PENDING | INTERRUPTER_ENABLE),
    );

    const command_offset = @as(u32, capabilities.capability_length) + OPERATIONAL_USB_COMMAND_OFFSET;
    const command = mmio.readReg32(command_offset);
    const enable_mask = USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE |
        USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE;
    mmio.writeReg32(command_offset, command & ~enable_mask);
}

pub fn controllerRunningHealthy(
    capabilities: CapabilityRegisters,
    mmio: anytype,
) bool {
    const operational_base: u32 = capabilities.capability_length;
    const status = mmio.readReg32(operational_base + OPERATIONAL_USB_STATUS_OFFSET);
    const fatal_status = USB_STATUS_HOST_SYSTEM_ERROR |
        USB_STATUS_CONTROLLER_NOT_READY |
        USB_STATUS_HOST_CONTROLLER_ERROR;
    if ((status & (USB_STATUS_HOST_CONTROLLER_HALTED | fatal_status)) != 0) return false;
    return (mmio.readReg32(operational_base + OPERATIONAL_USB_COMMAND_OFFSET) &
        USB_COMMAND_RUN_STOP) != 0;
}

pub fn acknowledgePrimaryEventRing(
    capabilities: CapabilityRegisters,
    dequeue_address: u64,
    mmio: anytype,
) Error!void {
    if ((dequeue_address & ~EVENT_RING_DEQUEUE_POINTER_MASK) != 0) {
        return error.EventRingStateInvalid;
    }
    const primary_interrupter = std.math.add(
        u32,
        capabilities.runtime_register_offset,
        PRIMARY_INTERRUPTER_OFFSET,
    ) catch return error.DmaLayoutOverflow;
    const erdp_offset = primary_interrupter + EVENT_RING_DEQUEUE_POINTER_OFFSET;
    mmio.writeReg64(erdp_offset, dequeue_address | EVENT_HANDLER_BUSY);
    if ((mmio.readReg64(erdp_offset) & EVENT_RING_DEQUEUE_POINTER_MASK) != dequeue_address) {
        return error.DmaRegisterRejected;
    }
}

pub fn configureDeviceSlots(
    capabilities: CapabilityRegisters,
    mmio: anytype,
) Error!u8 {
    const operational_base: u32 = capabilities.capability_length;
    const status = mmio.readReg32(operational_base + OPERATIONAL_USB_STATUS_OFFSET);
    if ((status & (USB_STATUS_CONTROLLER_NOT_READY | USB_STATUS_HOST_CONTROLLER_ERROR)) != 0 or
        (status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0)
    {
        return error.ControllerConfigurationUnavailable;
    }

    const enabled_slots = @min(capabilities.max_device_slots, maxDeviceSlotsU8());
    if (enabled_slots == 0) return error.MissingDeviceSlots;

    const configure_offset = operational_base + OPERATIONAL_CONFIGURE_OFFSET;
    const current = mmio.readReg32(configure_offset);
    const desired = (current & ~CONFIG_MAX_DEVICE_SLOTS_ENABLED_MASK) | @as(u32, enabled_slots);
    mmio.writeReg32(configure_offset, desired);
    const readback = mmio.readReg32(configure_offset);
    if ((readback & CONFIG_MAX_DEVICE_SLOTS_ENABLED_MASK) != enabled_slots) {
        return error.DeviceSlotConfigurationRejected;
    }
    return enabled_slots;
}

pub fn programControllerDmaRegisters(
    capabilities: CapabilityRegisters,
    plan: ControllerDmaPlan,
    mmio: anytype,
) Error!void {
    const operational_base: u32 = capabilities.capability_length;
    const status = mmio.readReg32(operational_base + OPERATIONAL_USB_STATUS_OFFSET);
    if ((status & (USB_STATUS_CONTROLLER_NOT_READY | USB_STATUS_HOST_CONTROLLER_ERROR)) != 0 or
        (status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0)
    {
        return error.DmaProgrammingUnavailable;
    }
    if ((mmio.readReg32(operational_base + OPERATIONAL_PAGE_SIZE_OFFSET) &
        PAGE_SIZE_4K_SUPPORTED) == 0)
    {
        return error.UnsupportedPageSize;
    }
    const command_ring_control_offset = operational_base + OPERATIONAL_COMMAND_RING_CONTROL_OFFSET;
    if ((mmio.readReg64(command_ring_control_offset) & COMMAND_RING_RUNNING) != 0) {
        return error.DmaProgrammingUnavailable;
    }

    const dcbaap_offset = operational_base + OPERATIONAL_DEVICE_CONTEXT_BASE_ARRAY_POINTER_OFFSET;
    mmio.writeReg64(dcbaap_offset, plan.arena.dcbaa_address);
    mmio.writeReg64(
        command_ring_control_offset,
        plan.ring_plan.command_ring_address | COMMAND_RING_INITIAL_CYCLE_STATE,
    );

    const primary_interrupter = std.math.add(
        u32,
        capabilities.runtime_register_offset,
        PRIMARY_INTERRUPTER_OFFSET,
    ) catch return error.DmaLayoutOverflow;
    const iman_offset = primary_interrupter + INTERRUPTER_MANAGEMENT_OFFSET;
    mmio.writeReg32(iman_offset, mmio.readReg32(iman_offset) & ~INTERRUPTER_ENABLE);
    mmio.writeReg32(
        primary_interrupter + INTERRUPTER_MODERATION_OFFSET,
        INTERRUPTER_MODERATION_INTERVAL_125_MICROSECONDS,
    );
    mmio.writeReg32(
        primary_interrupter + EVENT_RING_SEGMENT_TABLE_SIZE_OFFSET,
        plan.event_ring_segment_table_entries,
    );
    mmio.writeReg64(
        primary_interrupter + EVENT_RING_SEGMENT_TABLE_BASE_OFFSET,
        plan.event_ring_segment_table_address,
    );
    mmio.writeReg64(
        primary_interrupter + EVENT_RING_DEQUEUE_POINTER_OFFSET,
        plan.ring_plan.event_ring_address,
    );

    if ((mmio.readReg64(dcbaap_offset) & ~ADDRESS_64_BYTE_ALIGNMENT_MASK) !=
        plan.arena.dcbaa_address or
        (mmio.readReg32(iman_offset) & INTERRUPTER_ENABLE) != 0 or
        (mmio.readReg32(primary_interrupter + INTERRUPTER_MODERATION_OFFSET) & 0xFFFF) !=
            INTERRUPTER_MODERATION_INTERVAL_125_MICROSECONDS or
        (mmio.readReg32(primary_interrupter + EVENT_RING_SEGMENT_TABLE_SIZE_OFFSET) & 0xFFFF) !=
            plan.event_ring_segment_table_entries or
        (mmio.readReg64(primary_interrupter + EVENT_RING_SEGMENT_TABLE_BASE_OFFSET) &
            ~ADDRESS_64_BYTE_ALIGNMENT_MASK) != plan.event_ring_segment_table_address or
        (mmio.readReg64(primary_interrupter + EVENT_RING_DEQUEUE_POINTER_OFFSET) &
            EVENT_RING_DEQUEUE_POINTER_MASK) != plan.ring_plan.event_ring_address)
    {
        return error.DmaRegisterRejected;
    }
}

const MockOwnershipDeadline = struct {
    remaining_checks: usize,

    pub fn expired(self: *@This()) bool {
        if (self.remaining_checks == 0) return true;
        self.remaining_checks -= 1;
        return false;
    }
};

const ScriptedOperationalMmio = struct {
    command_offset: u32,
    status_offset: u32,
    command_reads: []const u32,
    status_reads: []const u32,
    command_read_index: usize = 0,
    status_read_index: usize = 0,
    writes: [4]u32 = @as([4]u32, @splat(0)),
    write_count: usize = 0,

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        if (offset == self.command_offset) {
            const index = @min(self.command_read_index, self.command_reads.len - 1);
            self.command_read_index += 1;
            return self.command_reads[index];
        }
        if (offset == self.status_offset) {
            const index = @min(self.status_read_index, self.status_reads.len - 1);
            self.status_read_index += 1;
            return self.status_reads[index];
        }
        unreachable;
    }

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        if (offset != self.command_offset or self.write_count == self.writes.len) unreachable;
        self.writes[self.write_count] = value;
        self.write_count += 1;
    }
};

fn scriptedOperationalMmio(command_reads: []const u32, status_reads: []const u32) ScriptedOperationalMmio {
    return .{
        .command_offset = @as(u32, TEST_CAPABILITY_LENGTH) + OPERATIONAL_USB_COMMAND_OFFSET,
        .status_offset = @as(u32, TEST_CAPABILITY_LENGTH) + OPERATIONAL_USB_STATUS_OFFSET,
        .command_reads = command_reads,
        .status_reads = status_reads,
    };
}

const MockResetClock = struct {
    deadline_checks: usize,
    requested_milliseconds: [4]u64 = @as([4]u64, @splat(0)),
    request_count: usize = 0,

    pub fn afterMilliseconds(self: *@This(), milliseconds: u64) MockOwnershipDeadline {
        if (self.request_count == self.requested_milliseconds.len) unreachable;
        self.requested_milliseconds[self.request_count] = milliseconds;
        self.request_count += 1;
        return .{ .remaining_checks = self.deadline_checks };
    }
};

test "xHCI reset quiesces a running controller and completes bounded handshakes" {
    const preserved_command_bit: u32 = 1 << 14;
    const command_reads = [_]u32{
        preserved_command_bit | USB_COMMAND_RUN_STOP | USB_COMMAND_INTERRUPTER_ENABLE | USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE,
        preserved_command_bit,
        USB_COMMAND_HOST_CONTROLLER_RESET,
        0,
    };
    const status_reads = [_]u32{
        USB_STATUS_CONTROLLER_NOT_READY,
        0,
        0,
        USB_STATUS_HOST_CONTROLLER_HALTED,
        USB_STATUS_CONTROLLER_NOT_READY,
        USB_STATUS_HOST_CONTROLLER_HALTED,
    };
    var mmio = scriptedOperationalMmio(&command_reads, &status_reads);
    var clock = MockResetClock{ .deadline_checks = 2 };
    try resetOwnedController(TEST_CAPABILITY_LENGTH, &mmio, &clock);
    try std.testing.expectEqual(@as(usize, 2), mmio.write_count);
    try std.testing.expectEqual(preserved_command_bit, mmio.writes[0]);
    try std.testing.expectEqual(
        preserved_command_bit | USB_COMMAND_HOST_CONTROLLER_RESET,
        mmio.writes[1],
    );
    try std.testing.expectEqualSlices(u64, &.{
        CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS,
        CONTROLLER_HALT_TIMEOUT_MILLISECONDS,
        CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS,
        CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS,
    }, clock.requested_milliseconds[0..clock.request_count]);
}

test "xHCI reset skips the halt write when the controller is already stopped" {
    const command_reads = [_]u32{
        USB_COMMAND_INTERRUPTER_ENABLE | USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE,
        USB_COMMAND_HOST_CONTROLLER_RESET,
        0,
    };
    const status_reads = [_]u32{
        USB_STATUS_HOST_CONTROLLER_HALTED,
        USB_STATUS_HOST_CONTROLLER_HALTED,
    };
    var mmio = scriptedOperationalMmio(&command_reads, &status_reads);
    var clock = MockResetClock{ .deadline_checks = 2 };
    try resetOwnedController(TEST_CAPABILITY_LENGTH, &mmio, &clock);
    try std.testing.expectEqual(@as(usize, 1), mmio.write_count);
    try std.testing.expectEqual(USB_COMMAND_HOST_CONTROLLER_RESET, mmio.writes[0]);
}

test "xHCI reset fails closed on ready, halt, reset, and final-state faults" {
    const no_command = [_]u32{0};
    const never_ready = [_]u32{USB_STATUS_CONTROLLER_NOT_READY};
    var mmio = scriptedOperationalMmio(&no_command, &never_ready);
    var expired = MockResetClock{ .deadline_checks = 0 };
    try std.testing.expectError(error.ControllerNotReadyTimeout, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));

    const running = [_]u32{0};
    mmio = scriptedOperationalMmio(&no_command, &running);
    expired = .{ .deadline_checks = 0 };
    try std.testing.expectError(error.ControllerHaltTimeout, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));

    const reset_stuck = [_]u32{ 0, USB_COMMAND_HOST_CONTROLLER_RESET };
    const halted = [_]u32{USB_STATUS_HOST_CONTROLLER_HALTED};
    mmio = scriptedOperationalMmio(&reset_stuck, &halted);
    expired = .{ .deadline_checks = 0 };
    try std.testing.expectError(error.ControllerResetTimeout, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));

    const reset_completes = [_]u32{ 0, USB_COMMAND_HOST_CONTROLLER_RESET, 0 };
    const ready_then_stuck = [_]u32{ USB_STATUS_HOST_CONTROLLER_HALTED, USB_STATUS_CONTROLLER_NOT_READY };
    mmio = scriptedOperationalMmio(&reset_completes, &ready_then_stuck);
    expired = .{ .deadline_checks = 1 };
    try std.testing.expectError(error.ControllerNotReadyTimeout, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));

    const failed_state = [_]u32{
        USB_STATUS_HOST_CONTROLLER_HALTED,
        USB_STATUS_HOST_CONTROLLER_HALTED | USB_STATUS_HOST_CONTROLLER_ERROR,
    };
    mmio = scriptedOperationalMmio(&reset_completes, &failed_state);
    expired = .{ .deadline_checks = 1 };
    try std.testing.expectError(error.ControllerResetFailed, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));
}

const MockStartMmio = struct {
    capabilities: CapabilityRegisters = defaultCapabilityRegisters(),
    command: u32 = 1 << 14,
    iman: u32 = 0,
    erdp: u64 = 0,
    last_erdp_write: u64 = 0,
    status_reads: []const u32,
    status_read_index: usize = 0,

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        const operational_base: u32 = self.capabilities.capability_length;
        if (offset == operational_base + OPERATIONAL_USB_COMMAND_OFFSET) return self.command;
        if (offset == operational_base + OPERATIONAL_USB_STATUS_OFFSET) {
            const index = @min(self.status_read_index, self.status_reads.len - 1);
            self.status_read_index += 1;
            return self.status_reads[index];
        }
        const iman_offset = self.capabilities.runtime_register_offset +
            PRIMARY_INTERRUPTER_OFFSET + INTERRUPTER_MANAGEMENT_OFFSET;
        if (offset == iman_offset) return self.iman;
        unreachable;
    }

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        const operational_base: u32 = self.capabilities.capability_length;
        if (offset == operational_base + OPERATIONAL_USB_COMMAND_OFFSET) {
            self.command = value;
            return;
        }
        const iman_offset = self.capabilities.runtime_register_offset +
            PRIMARY_INTERRUPTER_OFFSET + INTERRUPTER_MANAGEMENT_OFFSET;
        if (offset == iman_offset) {
            self.iman = value;
            return;
        }
        unreachable;
    }

    pub fn readReg64(self: *@This(), offset: u32) u64 {
        const erdp_offset = self.capabilities.runtime_register_offset +
            PRIMARY_INTERRUPTER_OFFSET + EVENT_RING_DEQUEUE_POINTER_OFFSET;
        if (offset != erdp_offset) unreachable;
        return self.erdp;
    }

    pub fn writeReg64(self: *@This(), offset: u32, value: u64) void {
        const erdp_offset = self.capabilities.runtime_register_offset +
            PRIMARY_INTERRUPTER_OFFSET + EVENT_RING_DEQUEUE_POINTER_OFFSET;
        if (offset != erdp_offset) unreachable;
        self.last_erdp_write = value;
        self.erdp = value & EVENT_RING_DEQUEUE_POINTER_MASK;
    }
};

test "xHCI start enables the primary interrupter before the schedule" {
    const halted_then_running = [_]u32{
        USB_STATUS_HOST_CONTROLLER_HALTED,
        USB_STATUS_HOST_CONTROLLER_HALTED,
        0,
    };
    var mmio = MockStartMmio{ .status_reads = &halted_then_running };
    var clock = MockResetClock{ .deadline_checks = 2 };
    try startOwnedController(mmio.capabilities, &mmio, &clock);

    const expected_enable_mask = USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE |
        USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE;
    try std.testing.expectEqual(expected_enable_mask, mmio.command & expected_enable_mask);
    try std.testing.expectEqual(INTERRUPTER_ENABLE, mmio.iman & INTERRUPTER_ENABLE);
    try std.testing.expectEqual(@as(usize, 1), clock.request_count);
    try std.testing.expect(controllerRunningHealthy(mmio.capabilities, &mmio));
}

test "xHCI start failure restores a quiescent controller" {
    const halted = [_]u32{USB_STATUS_HOST_CONTROLLER_HALTED};
    var mmio = MockStartMmio{ .status_reads = &halted };
    var expired = MockResetClock{ .deadline_checks = 0 };
    try std.testing.expectError(
        error.ControllerStartTimeout,
        startOwnedController(mmio.capabilities, &mmio, &expired),
    );
    try std.testing.expectEqual(@as(u32, 0), mmio.command & (USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE | USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE));
    try std.testing.expectEqual(@as(u32, 0), mmio.iman & INTERRUPTER_ENABLE);

    const host_error = [_]u32{
        USB_STATUS_HOST_CONTROLLER_HALTED | USB_STATUS_HOST_SYSTEM_ERROR,
    };
    mmio = .{ .status_reads = &host_error };
    expired = .{ .deadline_checks = 1 };
    try std.testing.expectError(
        error.ControllerStartUnavailable,
        startOwnedController(mmio.capabilities, &mmio, &expired),
    );
}

test "xHCI PORTSC writes preserve sticky controls and acknowledge only changes" {
    const status_value = PORT_CURRENT_CONNECT_STATUS |
        PORT_ENABLED_DISABLED |
        PORT_OVER_CURRENT_ACTIVE |
        PORT_RESET |
        (@as(u32, 5) << PORT_LINK_STATE_SHIFT) |
        PORT_POWER |
        (@as(u32, 3) << PORT_SPEED_SHIFT) |
        (@as(u32, 2) << 14) |
        (@as(u32, 0b1010101) << 17) |
        PORT_COLD_ATTACH_STATUS |
        (@as(u32, 0b101) << 25) |
        (@as(u32, 1) << 31);
    const status = decodePortStatus(status_value);
    try std.testing.expect(status.connected);
    try std.testing.expect(status.enabled);
    try std.testing.expect(status.over_current);
    try std.testing.expect(status.reset_active);
    try std.testing.expectEqual(@as(u4, 5), status.link_state);
    try std.testing.expectEqual(@as(u4, 3), status.speed);
    try std.testing.expect(status.cold_attach);
    try std.testing.expectEqual(@as(u7, 0b1010101), status.change_bits);

    const acknowledge = portStatusAcknowledge(status_value);
    try std.testing.expectEqual(status_value & (PORT_READ_WRITE_STICKY_MASK | PORT_CHANGE_MASK), acknowledge);
    try std.testing.expectEqual(
        @as(u32, 0),
        acknowledge & (PORT_ENABLED_DISABLED | PORT_RESET |
            (@as(u32, 1) << 16) | (@as(u32, 1) << 31)),
    );
    try std.testing.expect((portResetWrite(status_value, .{ .kind = .usb2, .slot_type = 0 }) & PORT_RESET) != 0);
    try std.testing.expect((portResetWrite(status_value, .{ .kind = .usb3, .slot_type = 1 }) & (@as(u32, 1) << 31)) != 0);
}

test "xHCI event acknowledgement clears EHB at the next dequeue address" {
    const running = [_]u32{0};
    var mmio = MockStartMmio{ .status_reads = &running };
    try acknowledgePrimaryEventRing(mmio.capabilities, 0x2040, &mmio);
    try std.testing.expectEqual(@as(u64, 0x2040) | EVENT_HANDLER_BUSY, mmio.last_erdp_write);
    try std.testing.expectError(
        error.EventRingStateInvalid,
        acknowledgePrimaryEventRing(mmio.capabilities, 0x2041, &mmio),
    );
}

const MockConfigurationMmio = struct {
    status: u32 = USB_STATUS_HOST_CONTROLLER_HALTED,
    configuration: u32 = 0,
    accept_write: bool = true,
    write_count: usize = 0,

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        const operational_base: u32 = TEST_CAPABILITY_LENGTH;
        if (offset == operational_base + OPERATIONAL_USB_STATUS_OFFSET) return self.status;
        if (offset == operational_base + OPERATIONAL_CONFIGURE_OFFSET) return self.configuration;
        unreachable;
    }

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        if (offset != @as(u32, TEST_CAPABILITY_LENGTH) + OPERATIONAL_CONFIGURE_OFFSET) unreachable;
        self.write_count += 1;
        if (self.accept_write) self.configuration = value;
    }
};

test "xHCI post-reset configuration caps enabled slots to kernel capacity" {
    const preserved_configuration: u32 = (1 << 8) | (1 << 10) | (1 << 20);
    var mmio = MockConfigurationMmio{ .configuration = preserved_configuration };
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 64;

    try std.testing.expectEqual(maxDeviceSlotsU8(), try configureDeviceSlots(capabilities, &mmio));
    try std.testing.expectEqual(@as(usize, 1), mmio.write_count);
    try std.testing.expectEqual(
        preserved_configuration | @as(u32, maxDeviceSlotsU8()),
        mmio.configuration,
    );

    capabilities.max_device_slots = 16;
    mmio = .{};
    try std.testing.expectEqual(@as(u8, 16), try configureDeviceSlots(capabilities, &mmio));
    try std.testing.expectEqual(@as(u32, 16), mmio.configuration);
}

test "xHCI post-reset configuration requires a ready halted controller and accepted readback" {
    const capabilities = defaultCapabilityRegisters();
    var mmio = MockConfigurationMmio{ .status = 0 };
    try std.testing.expectError(
        error.ControllerConfigurationUnavailable,
        configureDeviceSlots(capabilities, &mmio),
    );
    try std.testing.expectEqual(@as(usize, 0), mmio.write_count);

    mmio = .{ .status = USB_STATUS_HOST_CONTROLLER_HALTED | USB_STATUS_CONTROLLER_NOT_READY };
    try std.testing.expectError(
        error.ControllerConfigurationUnavailable,
        configureDeviceSlots(capabilities, &mmio),
    );

    mmio = .{ .accept_write = false };
    try std.testing.expectError(
        error.DeviceSlotConfigurationRejected,
        configureDeviceSlots(capabilities, &mmio),
    );
    try std.testing.expectEqual(@as(usize, 1), mmio.write_count);
}

const MockDmaRegisterMmio = struct {
    registers: [0x1100]u8 = @as([0x1100]u8, @splat(0)),
    accept_writes: bool = true,

    fn ready() @This() {
        var mmio = @This(){};
        writeU32Le(
            mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_USB_STATUS_OFFSET ..][0..4],
            USB_STATUS_HOST_CONTROLLER_HALTED,
        );
        writeU32Le(
            mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_PAGE_SIZE_OFFSET ..][0..4],
            PAGE_SIZE_4K_SUPPORTED,
        );
        return mmio;
    }

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        return readU32Le(self.registers[@as(usize, offset)..][0..4]);
    }

    pub fn readReg64(self: *@This(), offset: u32) u64 {
        return readU64Le(self.registers[@as(usize, offset)..][0..8]);
    }

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        if (self.accept_writes) writeU32Le(self.registers[@as(usize, offset)..][0..4], value);
    }

    pub fn writeReg64(self: *@This(), offset: u32, value: u64) void {
        if (self.accept_writes) writeU64Le(self.registers[@as(usize, offset)..][0..8], value);
    }
};

test "xHCI halted DMA register programming initializes the primary event ring" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_scratchpad_buffers = 0;
    capabilities.scratchpad_restore = false;
    const plan = try planControllerDma(capabilities, TEST_MAX_DEVICE_SLOTS, 0x4000);
    var mmio = MockDmaRegisterMmio.ready();
    try programControllerDmaRegisters(capabilities, plan, &mmio);

    const operational_base: u32 = capabilities.capability_length;
    try std.testing.expectEqual(
        plan.arena.dcbaa_address,
        mmio.readReg64(operational_base + OPERATIONAL_DEVICE_CONTEXT_BASE_ARRAY_POINTER_OFFSET),
    );
    try std.testing.expectEqual(
        plan.ring_plan.command_ring_address | COMMAND_RING_INITIAL_CYCLE_STATE,
        mmio.readReg64(operational_base + OPERATIONAL_COMMAND_RING_CONTROL_OFFSET),
    );
    const primary = capabilities.runtime_register_offset + PRIMARY_INTERRUPTER_OFFSET;
    try std.testing.expectEqual(
        INTERRUPTER_MODERATION_INTERVAL_125_MICROSECONDS,
        mmio.readReg32(primary + INTERRUPTER_MODERATION_OFFSET),
    );
    try std.testing.expectEqual(
        EVENT_RING_SEGMENT_TABLE_ENTRIES,
        mmio.readReg32(primary + EVENT_RING_SEGMENT_TABLE_SIZE_OFFSET),
    );
    try std.testing.expectEqual(
        plan.event_ring_segment_table_address,
        mmio.readReg64(primary + EVENT_RING_SEGMENT_TABLE_BASE_OFFSET),
    );
    try std.testing.expectEqual(
        plan.ring_plan.event_ring_address,
        mmio.readReg64(primary + EVENT_RING_DEQUEUE_POINTER_OFFSET),
    );
}

test "xHCI DMA register programming rejects unsafe controller states" {
    const capabilities = defaultCapabilityRegisters();
    const plan = try planControllerDma(capabilities, TEST_MAX_DEVICE_SLOTS, 0x4000);
    var mmio = MockDmaRegisterMmio.ready();
    writeU32Le(
        mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_USB_STATUS_OFFSET ..][0..4],
        0,
    );
    try std.testing.expectError(
        error.DmaProgrammingUnavailable,
        programControllerDmaRegisters(capabilities, plan, &mmio),
    );

    mmio = MockDmaRegisterMmio.ready();
    writeU32Le(
        mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_PAGE_SIZE_OFFSET ..][0..4],
        0,
    );
    try std.testing.expectError(
        error.UnsupportedPageSize,
        programControllerDmaRegisters(capabilities, plan, &mmio),
    );

    mmio = MockDmaRegisterMmio.ready();
    writeU64Le(
        mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_COMMAND_RING_CONTROL_OFFSET ..][0..8],
        COMMAND_RING_RUNNING,
    );
    try std.testing.expectError(
        error.DmaProgrammingUnavailable,
        programControllerDmaRegisters(capabilities, plan, &mmio),
    );

    mmio = MockDmaRegisterMmio.ready();
    mmio.accept_writes = false;
    try std.testing.expectError(
        error.DmaRegisterRejected,
        programControllerDmaRegisters(capabilities, plan, &mmio),
    );
}
