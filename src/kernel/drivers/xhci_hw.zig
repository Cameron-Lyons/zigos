const std = @import("std");
const console = @import("../utils/console.zig");
const endian = @import("../utils/endian.zig");
const mmio_windows = @import("../memory/mmio_windows.zig");
const paging = @import("../memory/paging64.zig");
const x2apic = @import("../interrupts/x2apic.zig");
const intel_vtd = @import("../platform/intel_vtd.zig");
const tsc_clock = @import("../timer/tsc_clock.zig");
const pci = @import("pci.zig");
const smp = @import("../smp.zig");
const xhci = @import("xhci.zig");

const PAGE_BYTES = mmio_windows.PAGE_BYTES;
const OWNERSHIP_TIMEOUT_MILLISECONDS: u64 = 1_000;
const PORT_RESET_TIMEOUT_MILLISECONDS: u64 = 1_000;
const COMMAND_TIMEOUT_MILLISECONDS: u64 = 1_000;
const CONTROL_TRANSFER_TIMEOUT_MILLISECONDS: u64 = 1_000;
const RETIREMENT_TIMEOUT_MILLISECONDS: u64 = 6 * COMMAND_TIMEOUT_MILLISECONDS;
const OS_OWNED_BYTE_OFFSET: usize = 3;
const PORT_RESET_COMPLETION_CHANGE_MASK: u7 = (1 << 2) | (1 << 4);

pub const INTERRUPT_VECTOR: u8 = 67;
pub const PORT_RUNTIME_STATE_SIZE_CEILING_BYTES: usize = 104;
pub const CONTROLLER_RUNTIME_STATE_MAX_FRAME_COUNT: usize = 7;
pub const COLOCATED_BOOT_KEYBOARD_REPORT_STATE = true;
pub const COLOCATED_SUPPORTED_PROTOCOL_STATE = true;
pub const INTERRUPT_STATE_USES_PROTOCOL_ORDERING = true;
pub const CONTROLLER_RUNTIME_STATE_USES_GENERAL_MEMORY = true;

comptime {
    if (xhci.CAPABILITY_REGISTERS_BYTES > mmio_windows.xhci.bytes) {
        @compileError("xHCI capability snapshot exceeds its reserved MMIO window");
    }
    if (xhci.XHCI_PAGE_BYTES != PAGE_BYTES) {
        @compileError("xHCI DMA and kernel page sizes must match");
    }
}

pub const Error = xhci.Error || error{
    NotXhciController,
    BarUnmappable,
    BarMisaligned,
    BarRangeOverflow,
    InvariantClockUnavailable,
    AlreadyPrepared,
    BusMasteringNotRevoked,
    DmaAllocationFailed,
    ControllerRuntimeStateAllocationFailed,
    DmaIsolationPlanInvalid,
    DmaIsolationBypassed,
    DmaFaultMonitoringUnavailable,
    InterruptIsolationUnavailable,
    InterruptRouteInstallFailed,
    MsiEnableFailed,
    BusMasterEnableFailed,
};

const ControllerDmaMemory = struct {
    physical_base: u32 = 0,
    alias_base: usize = 0,
    byte_len: usize = 0,

    fn bytes(self: ControllerDmaMemory) []u8 {
        return @as([*]u8, @ptrFromInt(self.alias_base))[0..self.byte_len];
    }

    fn aliasFor(
        self: ControllerDmaMemory,
        physical_address: u64,
        byte_len: usize,
    ) Error!usize {
        const base = @as(u64, self.physical_base);
        if (physical_address < base) return error.DmaAddressOutsidePlan;
        const offset = std.math.cast(usize, physical_address - base) orelse
            return error.DmaAddressOutsidePlan;
        if (offset > self.byte_len or byte_len > self.byte_len - offset) {
            return error.DmaAddressOutsidePlan;
        }
        return std.math.add(usize, self.alias_base, offset) catch
            return error.DmaAddressOutsidePlan;
    }
};

var active_capabilities: ?xhci.CapabilityRegisters = null;
var active_protocols: ?*const xhci.SupportedProtocols = null;
var active_legacy_ownership: ?xhci.LegacyOwnership = null;
var active_controller_reset = false;
var active_enabled_slots: u8 = 0;
var active_device: pci.PCIDevice = undefined;
var active_dma_plan: ?xhci.ControllerDmaPlan = null;
var active_dma_memory = ControllerDmaMemory{};
var active_dma_frame_count: u32 = 0;
var active_dma_windows: [xhci.MAX_CONTROLLER_DMA_REGIONS]intel_vtd.DmaWindow = undefined;
var active_dma_window_count: usize = 0;
var active_bar_address: usize = 0;
var active = false;
var event_consumer = xhci.EventRingConsumer{};
var command_producer = xhci.TrbRingProducer{};
var control_producers = @as([xhci.MAX_DEVICE_SLOTS + 1]xhci.TrbRingProducer, @splat(.{}));
var interrupt_producers = @as([xhci.MAX_DEVICE_SLOTS + 1]xhci.TrbRingProducer, @splat(.{}));
var slot_to_port = @as([xhci.MAX_DEVICE_SLOTS + 1]u8, @splat(0));
var active_keyboard_reports: ?*xhci.BootKeyboardReportPublisher = null;
var outstanding_interrupt_reports: usize = 0;
var pending_interrupts: u32 = 0;
var interrupt_count: u64 = 0;
var event_count: u64 = 0;
var port_status_change_count: u64 = 0;
var command_completion_count: u64 = 0;
var transfer_completion_count: u64 = 0;
var descriptor_prefix_count: u64 = 0;
var device_descriptor_count: u64 = 0;
var configuration_descriptor_header_count: u64 = 0;
var configuration_descriptor_count: u64 = 0;
var set_configuration_count: u64 = 0;
var set_boot_protocol_count: u64 = 0;
var configure_endpoint_count: u64 = 0;
var interrupt_report_submission_count: u64 = 0;
var keyboard_report_count: u64 = 0;
// Never reset with controller counters: a reclaimed USB slot is a new input
// lifetime even when the replacement reports the same device identity.
var keyboard_continuity_epoch: u64 = 1;

fn controllerActive() bool {
    return @atomicLoad(bool, &active, .acquire);
}

fn publishControllerActive(value: bool) void {
    if (!value) keyboard_continuity_epoch +|= 1;
    @atomicStore(bool, &active, value, .release);
}

fn resetInterruptAccounting() void {
    @atomicStore(u32, &pending_interrupts, 0, .monotonic);
    @atomicStore(u64, &interrupt_count, 0, .monotonic);
}

const PortAction = enum(u8) {
    none,
    enable_slot,
    address_device,
    read_device_descriptor_prefix,
    evaluate_endpoint_zero,
    read_device_descriptor,
    read_configuration_descriptor_header,
    read_configuration_descriptor,
    set_configuration,
    set_boot_protocol,
    configure_endpoint,
    post_interrupt_report,
    disable_slot,
    retire_slot,
    reset_port,
};

const PortRuntimeState = struct {
    connected: bool = false,
    retiring: bool = false,
    endpoint_state: packed struct(u8) {
        failed_mask: u2 = 0,
        stopped_mask: u2 = 0,
        reserved: u4 = 0,
    } = .{},
    enabled: bool = false,
    addressed: bool = false,
    descriptor_prefix_valid: bool = false,
    device_descriptor: ?xhci.UsbDeviceDescriptor = null,
    configuration_descriptor_header: ?xhci.UsbConfigurationDescriptor = null,
    configuration_descriptor: ?xhci.UsbConfigurationDescriptor = null,
    boot_keyboard: ?xhci.UsbBootKeyboardConfiguration = null,
    configuration_set: bool = false,
    boot_protocol_set: bool = false,
    endpoint_configured: bool = false,
    speed_id: u4 = 0,
    slot_id: u8 = 0,
    endpoint_zero_max_packet_size: u16 = 0,
    pending_endpoint_zero_max_packet_size: u16 = 0,
    interrupt_report_trb_address: u64 = 0,
    reset_deadline: ?tsc_clock.Deadline = null,
    action: PortAction = .none,
};

const ControllerRuntimeStateAllocation = struct {
    frames: paging.FrameRun,
    states: []PortRuntimeState,
    keyboard_reports: *xhci.BootKeyboardReportPublisher,
    protocols: *const xhci.SupportedProtocols,
};

comptime {
    if (@sizeOf(PortRuntimeState) > PORT_RUNTIME_STATE_SIZE_CEILING_BYTES) {
        @compileError("xHCI port runtime state exceeds its compact size ceiling");
    }
    const maximum_state_count = @as(usize, std.math.maxInt(u8)) + 1;
    const maximum_state_bytes = maximum_state_count * @sizeOf(PortRuntimeState);
    const publisher_offset = std.mem.alignForward(
        usize,
        maximum_state_bytes,
        @alignOf(xhci.BootKeyboardReportPublisher),
    );
    const protocols_offset = std.mem.alignForward(
        usize,
        publisher_offset + @sizeOf(xhci.BootKeyboardReportPublisher),
        @alignOf(xhci.SupportedProtocols),
    );
    const maximum_runtime_bytes = protocols_offset + @sizeOf(xhci.SupportedProtocols);
    const maximum_frame_count = (maximum_runtime_bytes + PAGE_BYTES - 1) / PAGE_BYTES;
    if (maximum_frame_count > CONTROLLER_RUNTIME_STATE_MAX_FRAME_COUNT) {
        @compileError("xHCI controller runtime state exceeds its bounded frame ceiling");
    }
}

const OutstandingCommand = struct {
    kind: xhci.CommandKind,
    trb_address: u64,
    port_id: u8,
    slot_id: u8,
    endpoint_id: u5 = 0,
    stopped_event_seen: bool = false,
    state_error_seen: bool = false,
    deadline: tsc_clock.Deadline,
};

const ControlTransferKind = enum(u8) {
    device_descriptor_prefix,
    device_descriptor,
    configuration_descriptor_header,
    configuration_descriptor,
    set_configuration,
    set_boot_protocol,
};

const OutstandingTransfer = struct {
    kind: ControlTransferKind,
    status_trb_address: u64,
    port_id: u8,
    slot_id: u8,
    deadline: tsc_clock.Deadline,
};

var empty_port_runtime_states: [0]PortRuntimeState = .{};
var ports: []PortRuntimeState = empty_port_runtime_states[0..];
var active_controller_runtime_state_frames: ?paging.FrameRun = null;
var outstanding_command: ?OutstandingCommand = null;
var outstanding_transfer: ?OutstandingTransfer = null;
var next_port_scan: u16 = 1;

fn keyboardReportPublisherOffsetFor(max_ports: u8) usize {
    const state_count = @as(usize, max_ports) + 1;
    const state_bytes = state_count * @sizeOf(PortRuntimeState);
    return std.mem.alignForward(
        usize,
        state_bytes,
        @alignOf(xhci.BootKeyboardReportPublisher),
    );
}

fn controllerRuntimeStateFrameCountFor(max_ports: u8) u32 {
    const runtime_bytes = supportedProtocolsOffsetFor(max_ports) +
        @sizeOf(xhci.SupportedProtocols);
    return @intCast((runtime_bytes + PAGE_BYTES - 1) / PAGE_BYTES);
}

fn supportedProtocolsOffsetFor(max_ports: u8) usize {
    return std.mem.alignForward(
        usize,
        keyboardReportPublisherOffsetFor(max_ports) +
            @sizeOf(xhci.BootKeyboardReportPublisher),
        @alignOf(xhci.SupportedProtocols),
    );
}

fn allocateControllerRuntimeState(
    max_ports: u8,
    protocols: xhci.SupportedProtocols,
) Error!ControllerRuntimeStateAllocation {
    const state_count = @as(usize, max_ports) + 1;
    const publisher_offset = keyboardReportPublisherOffsetFor(max_ports);
    const protocols_offset = supportedProtocolsOffsetFor(max_ports);
    const frame_count = controllerRuntimeStateFrameCountFor(max_ports);
    const frames = paging.allocGeneralFrames(frame_count) orelse
        return error.ControllerRuntimeStateAllocationFailed;
    errdefer paging.releaseGeneralFrames(frames) catch {};
    const allocation_bytes = @as(usize, frame_count) * PAGE_BYTES;
    const base = paging.directMapAddress(frames.base) orelse
        return error.ControllerRuntimeStateAllocationFailed;
    const bytes: [*]u8 = @ptrFromInt(base);
    @memset(bytes[0..allocation_bytes], 0);
    const state_pointer: [*]PortRuntimeState = @ptrFromInt(base);
    const states = state_pointer[0..state_count];
    for (states) |*state| state.* = .{};
    const keyboard_reports: *xhci.BootKeyboardReportPublisher =
        @ptrFromInt(@as(usize, base) + publisher_offset);
    keyboard_reports.* = .{};
    const protocol_state: *xhci.SupportedProtocols =
        @ptrFromInt(@as(usize, base) + protocols_offset);
    protocol_state.* = protocols;
    return .{
        .frames = frames,
        .states = states,
        .keyboard_reports = keyboard_reports,
        .protocols = protocol_state,
    };
}

fn resetControllerRuntimeState() void {
    for (ports) |*state| state.* = .{};
    if (active_keyboard_reports) |reports| reports.* = .{};
}

inline fn keyboardReports() *xhci.BootKeyboardReportPublisher {
    return active_keyboard_reports orelse unreachable;
}

pub fn probe(device_info: pci.PCIDevice) Error!xhci.CapabilityRegisters {
    if (active_dma_plan != null) return error.AlreadyPrepared;
    if (pci.busMasteringEnabled(device_info)) return error.BusMasteringNotRevoked;
    active_capabilities = null;
    active_protocols = null;
    active_legacy_ownership = null;
    active_controller_reset = false;
    active_enabled_slots = 0;
    active_dma_memory = .{};
    active_bar_address = 0;
    publishControllerActive(false);
    event_consumer = .{};
    command_producer = .{};
    control_producers = @as([xhci.MAX_DEVICE_SLOTS + 1]xhci.TrbRingProducer, @splat(.{}));
    interrupt_producers = @as([xhci.MAX_DEVICE_SLOTS + 1]xhci.TrbRingProducer, @splat(.{}));
    slot_to_port = @as([xhci.MAX_DEVICE_SLOTS + 1]u8, @splat(0));
    active_keyboard_reports = null;
    outstanding_interrupt_reports = 0;
    ports = empty_port_runtime_states[0..];
    active_controller_runtime_state_frames = null;
    outstanding_command = null;
    outstanding_transfer = null;
    next_port_scan = 1;
    resetInterruptAccounting();
    event_count = 0;
    port_status_change_count = 0;
    command_completion_count = 0;
    transfer_completion_count = 0;
    descriptor_prefix_count = 0;
    device_descriptor_count = 0;
    configuration_descriptor_header_count = 0;
    configuration_descriptor_count = 0;
    set_configuration_count = 0;
    set_boot_protocol_count = 0;
    configure_endpoint_count = 0;
    interrupt_report_submission_count = 0;
    keyboard_report_count = 0;
    const bar = try validateBar(device_info);
    paging.mapKernelBorrowedPage(
        mmio_windows.xhci.base,
        bar.address,
        paging.PAGE_PRESENT | paging.PAGE_CACHE_DISABLE,
    );
    const snapshot = readCapabilitySnapshot(mmio_windows.xhci.base);
    const capabilities = try xhci.parseCapabilityRegisters(&snapshot);
    try validateExtendedCapabilityRange(bar.address, capabilities.extended_capability_offset);
    try validateControllerRegisterRanges(bar.address, capabilities);
    if (!tsc_clock.initialized()) return error.InvariantClockUnavailable;
    var reader = ExtendedCapabilityReader{ .bar_address = bar.address };
    const protocols = try xhci.parseSupportedProtocols(
        capabilities,
        capabilities.extended_capability_offset,
        &reader,
    );
    const legacy = try xhci.findLegacySupport(capabilities.extended_capability_offset, &reader);
    const legacy_ownership = if (legacy) |support| ownership: {
        break :ownership try xhci.claimLegacyOwnership(
            support,
            &reader,
            tsc_clock.afterMilliseconds(OWNERSHIP_TIMEOUT_MILLISECONDS),
        );
    } else xhci.LegacyOwnership.not_present;
    try xhci.resetOwnedController(capabilities.capability_length, &reader, InvariantClock{});
    const enabled_slots = try xhci.configureDeviceSlots(capabilities, &reader);

    const controller_runtime_state = try allocateControllerRuntimeState(
        capabilities.max_ports,
        protocols,
    );
    var retain_controller_runtime_state = false;
    errdefer if (!retain_controller_runtime_state) paging.releaseGeneralFrames(
        controller_runtime_state.frames,
    ) catch {};
    const dma_frame_count = try xhci.controllerDmaFrameCount(capabilities, enabled_slots);
    const dma_base = paging.allocIdentityDmaFrames(dma_frame_count) orelse return error.DmaAllocationFailed;
    var retain_dma_frames = false;
    errdefer if (!retain_dma_frames) paging.releaseIdentityDmaFrames(dma_base, dma_frame_count) catch {};
    const dma_plan = try xhci.planControllerDma(capabilities, enabled_slots, dma_base);
    if (try dma_plan.frameCount() > dma_frame_count) return error.DmaIsolationPlanInvalid;
    const dma_bytes = std.math.cast(usize, dma_plan.total_bytes) orelse
        return error.DmaIsolationPlanInvalid;
    const dma_memory = ControllerDmaMemory{
        .physical_base = dma_base,
        .alias_base = paging.directMapAddress(dma_base) orelse return error.DmaAllocationFailed,
        .byte_len = dma_bytes,
    };
    try xhci.initializeControllerDma(dma_plan, dma_memory.bytes());
    publishDmaStructures();
    try xhci.programControllerDmaRegisters(capabilities, dma_plan, &reader);
    const dma_window_count = try buildDmaWindows(dma_plan, &active_dma_windows);

    active_device = device_info;
    active_dma_plan = dma_plan;
    active_dma_memory = dma_memory;
    active_dma_frame_count = dma_frame_count;
    active_dma_window_count = dma_window_count;
    active_bar_address = bar.address;
    active_capabilities = capabilities;
    active_protocols = controller_runtime_state.protocols;
    active_legacy_ownership = legacy_ownership;
    active_controller_reset = true;
    active_enabled_slots = enabled_slots;
    ports = controller_runtime_state.states;
    active_keyboard_reports = controller_runtime_state.keyboard_reports;
    active_controller_runtime_state_frames = controller_runtime_state.frames;
    retain_controller_runtime_state = true;
    retain_dma_frames = true;
    return capabilities;
}

pub fn validated() bool {
    const capabilities = active_capabilities orelse return false;
    const ownership = active_legacy_ownership orelse return false;
    const runtime_frames = active_controller_runtime_state_frames orelse return false;
    return active_protocols != null and
        ownership != .firmware_released and
        active_controller_reset and
        active_enabled_slots != 0 and
        runtime_frames.count == controllerRuntimeStateFrameCountFor(capabilities.max_ports) and
        active_keyboard_reports != null and
        ports.len == @as(usize, capabilities.max_ports) + 1 and
        active_dma_plan != null and
        active_dma_memory.byte_len != 0 and
        active_dma_window_count != 0;
}

pub fn probedCapabilities() ?xhci.CapabilityRegisters {
    return active_capabilities;
}

pub fn publishedBar() ?struct { physical_base: u64, length: u64 } {
    if (active_bar_address == 0) return null;
    return .{ .physical_base = active_bar_address, .length = PAGE_BYTES };
}

pub fn probedLegacyOwnership() ?xhci.LegacyOwnership {
    return active_legacy_ownership;
}

pub fn controllerReset() bool {
    return active_controller_reset;
}

pub fn enabledDeviceSlots() u8 {
    return active_enabled_slots;
}

pub fn dmaPlan() ?xhci.ControllerDmaPlan {
    return active_dma_plan;
}

pub fn dmaFrameCount() u32 {
    return active_dma_frame_count;
}

pub fn dmaBaseAddress() u32 {
    return active_dma_memory.physical_base;
}

pub fn isolationDomain() ?intel_vtd.DmaDomain {
    if (active_dma_plan == null or active_dma_window_count == 0) return null;
    return .{
        .device = active_device,
        .windows = active_dma_windows[0..active_dma_window_count],
    };
}

pub fn requesterIsolated() bool {
    return active_dma_plan != null and intel_vtd.requesterProtected(active_device);
}

pub fn controllerDeviceId() ?u64 {
    if (!controllerActive()) return null;
    return pci.stableDeviceId(active_device);
}

pub fn activate() Error!void {
    if (controllerActive()) return;
    if (!validated() or !intel_vtd.requesterProtected(active_device)) {
        return error.DmaIsolationBypassed;
    }
    if (!intel_vtd.faultMonitoringEnabled()) return error.DmaFaultMonitoringUnavailable;
    if (!intel_vtd.interruptIsolationEnabled()) return error.InterruptIsolationUnavailable;

    const capabilities = active_capabilities.?;
    var reader = ExtendedCapabilityReader{ .bar_address = active_bar_address };
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
    var bus_master_enabled = false;
    errdefer {
        publishControllerActive(false);
        xhci.quiesceOwnedController(capabilities, &reader);
        if (msi_enabled) pci.disableMsi(active_device) catch {};
        if (bus_master_enabled) pci.disableBusMastering(active_device);
    }

    pci.enableMemoryBusMastering(active_device);
    if (!pci.busMasteringEnabled(active_device)) {
        pci.disableBusMastering(active_device);
        return error.BusMasterEnableFailed;
    }
    bus_master_enabled = true;

    event_consumer = .{};
    command_producer = .{};
    control_producers = @as([xhci.MAX_DEVICE_SLOTS + 1]xhci.TrbRingProducer, @splat(.{}));
    interrupt_producers = @as([xhci.MAX_DEVICE_SLOTS + 1]xhci.TrbRingProducer, @splat(.{}));
    slot_to_port = @as([xhci.MAX_DEVICE_SLOTS + 1]u8, @splat(0));
    outstanding_interrupt_reports = 0;
    resetControllerRuntimeState();
    outstanding_command = null;
    outstanding_transfer = null;
    next_port_scan = 1;
    resetInterruptAccounting();
    event_count = 0;
    port_status_change_count = 0;
    command_completion_count = 0;
    transfer_completion_count = 0;
    descriptor_prefix_count = 0;
    device_descriptor_count = 0;
    configuration_descriptor_header_count = 0;
    configuration_descriptor_count = 0;
    set_configuration_count = 0;
    set_boot_protocol_count = 0;
    configure_endpoint_count = 0;
    interrupt_report_submission_count = 0;
    keyboard_report_count = 0;
    publishControllerActive(true);
    try xhci.startOwnedController(capabilities, &reader, InvariantClock{});
    msi_enabled = false;
    bus_master_enabled = false;
}

pub fn attached() bool {
    return controllerActive();
}

pub fn handleInterrupt() void {
    if (controllerActive()) {
        _ = @atomicRmw(u32, &pending_interrupts, .Add, 1, .monotonic);
        _ = @atomicRmw(u64, &interrupt_count, .Add, 1, .monotonic);
    }
    x2apic.acknowledge();
}

pub fn eventWorkPending() bool {
    if (!controllerActive()) return false;
    if (@atomicLoad(u32, &pending_interrupts, .monotonic) != 0) return true;
    return currentEventReady();
}

pub fn lifecyclePending() bool {
    if (!controllerActive()) return false;
    if (outstanding_command != null or outstanding_transfer != null) return true;
    const capabilities = active_capabilities orelse return false;
    var port_id: u16 = 1;
    while (port_id <= capabilities.max_ports) : (port_id += 1) {
        if (ports[port_id].reset_deadline != null or ports[port_id].action != .none) return true;
    }
    return false;
}

pub fn servicePendingEvents() usize {
    if (!controllerActive()) return 0;
    const interrupt_wakes = @atomicRmw(
        u32,
        &pending_interrupts,
        .Xchg,
        0,
        .monotonic,
    );
    const event_ready = currentEventReady();
    if (interrupt_wakes == 0 and !event_ready and !lifecyclePending()) return 0;
    if (pollDmaFault()) return 0;
    if (lifecycleTimedOut()) return 0;
    var reader = ExtendedCapabilityReader{ .bar_address = active_bar_address };
    if (interrupt_wakes == 0 and !event_ready) {
        submitNextPortAction(&reader) catch {
            containFailure("ZIGOS:XHCI:HW:COMMAND_SUBMIT_CONTAINED\n");
        };
        return 0;
    }

    const plan = active_dma_plan.?;
    var processed: usize = 0;
    while (processed < plan.ring_plan.event_ring_trbs) : (processed += 1) {
        const words = readCurrentEvent() orelse break;
        const event = event_consumer.consume(
            words,
            plan.ring_plan.event_ring_trbs,
        ) catch {
            containFailure("ZIGOS:XHCI:HW:EVENT_RING_STATE_CONTAINED\n");
            return processed;
        } orelse break;
        event_count +%= 1;
        handleEvent(event, &reader) catch {
            containFailure(switch (event.kind) {
                .port_status_change => "ZIGOS:XHCI:HW:PORT_EVENT_CONTAINED\n",
                .command_completion => "ZIGOS:XHCI:HW:COMMAND_EVENT_CONTAINED\n",
                .transfer => "ZIGOS:XHCI:HW:TRANSFER_EVENT_CONTAINED\n",
                else => "ZIGOS:XHCI:HW:CONTROLLER_EVENT_CONTAINED\n",
            });
            return processed + 1;
        };
    }

    const dequeue_address = event_consumer.dequeueAddress(
        plan.ring_plan.event_ring_address,
        plan.ring_plan.event_ring_trbs,
    ) catch {
        containFailure("ZIGOS:XHCI:HW:EVENT_RING_STATE_CONTAINED\n");
        return processed;
    };
    xhci.acknowledgePrimaryEventRing(
        active_capabilities.?,
        dequeue_address,
        &reader,
    ) catch {
        containFailure("ZIGOS:XHCI:HW:ERDP_REJECTED_CONTAINED\n");
        return processed;
    };
    if (!xhci.controllerRunningHealthy(active_capabilities.?, &reader)) {
        containFailure("ZIGOS:XHCI:HW:RUN_STATE_CONTAINED\n");
        return processed;
    }
    submitNextPortAction(&reader) catch {
        containFailure("ZIGOS:XHCI:HW:COMMAND_SUBMIT_CONTAINED\n");
    };
    return processed;
}

fn handleEvent(event: xhci.Event, reader: anytype) Error!void {
    switch (event.kind) {
        .port_status_change => {
            try handlePortStatusChange(event, reader);
            port_status_change_count +%= 1;
        },
        .command_completion => {
            try handleCommandCompletion(event, reader);
            command_completion_count +%= 1;
        },
        .transfer => {
            if (event.endpoint_id == xhci.ENDPOINT_ZERO_DCI) {
                try handleControlTransferCompletion(event, reader);
            } else {
                try handleInterruptTransferCompletion(event, reader);
            }
            transfer_completion_count +%= 1;
        },
        .host_controller, .vendor_defined, .unknown => return error.EventRingStateInvalid,
        .bandwidth_request, .doorbell, .device_notification, .mfindex_wrap => {},
    }
}

pub fn processedEventCount() u64 {
    return event_count;
}

pub fn portStatusChangeEventCount() u64 {
    return port_status_change_count;
}

pub fn commandCompletionEventCount() u64 {
    return command_completion_count;
}

pub fn transferCompletionEventCount() u64 {
    return transfer_completion_count;
}

pub fn deviceDescriptorPrefixCount() u64 {
    return descriptor_prefix_count;
}

pub fn deviceDescriptorCount() u64 {
    return device_descriptor_count;
}

pub fn configurationDescriptorHeaderCount() u64 {
    return configuration_descriptor_header_count;
}

pub fn configurationDescriptorCount() u64 {
    return configuration_descriptor_count;
}

pub fn setConfigurationCount() u64 {
    return set_configuration_count;
}

pub fn setBootProtocolCount() u64 {
    return set_boot_protocol_count;
}

pub fn configureEndpointCount() u64 {
    return configure_endpoint_count;
}

pub fn interruptReportSubmissionCount() u64 {
    return interrupt_report_submission_count;
}

pub fn keyboardReportCount() u64 {
    return keyboard_report_count;
}

pub fn keyboardContinuityEpoch() ?u64 {
    if (!controllerActive() or keyboard_continuity_epoch == std.math.maxInt(u64)) return null;
    return keyboard_continuity_epoch;
}

pub fn keyboardReportAfter(observed_sequence: u64) ?xhci.HardwareBootKeyboardReport {
    if (!controllerActive()) return null;
    return keyboardReports().latestAfter(observed_sequence);
}

pub fn pollKeyboardReport() ?xhci.HardwareBootKeyboardReport {
    if (!controllerActive()) return null;
    const report = keyboardReports().poll() orelse return null;
    scheduleUnarmedInterruptReports();
    return report;
}

pub fn inputProof() ?xhci.InputProof {
    if (!controllerActive()) return null;
    const report = keyboardReports().latestAfter(0) orelse return null;
    const state = &ports[report.port_id];
    _ = state.device_descriptor orelse return null;
    const keyboard = state.boot_keyboard orelse return null;
    if (state.retiring or !state.endpoint_configured or state.slot_id != report.slot_id or
        keyboard.endpoint_id != report.endpoint_id)
    {
        return null;
    }
    const capabilities = active_capabilities orelse return null;
    const plan = active_dma_plan orelse return null;
    const delivered_events = std.math.cast(usize, keyboard_report_count) orelse return null;
    const delivered_events_u32 = saturatingU32(keyboard_report_count);
    const control_doorbells = descriptor_prefix_count +| device_descriptor_count +|
        configuration_descriptor_header_count +| configuration_descriptor_count +|
        set_configuration_count +| set_boot_protocol_count;
    const input_report_dma_bytes = std.math.mul(
        u64,
        keyboard_report_count,
        xhci.HID_BOOT_KEYBOARD_REPORT_BYTES,
    ) catch std.math.maxInt(u64);
    return .{
        .keyboard = .{
            .device_id = pci.stableDeviceId(active_device),
            .port_id = report.port_id,
            .slot_id = report.slot_id,
            .interface_number = keyboard.interface_number,
            .endpoint_id = keyboard.endpoint_id,
            .max_packet_size = keyboard.max_packet_size,
            .interval = keyboard.interval,
        },
        .event_count = delivered_events,
        .mmio = .{
            .doorbell_offset = capabilities.doorbell_offset,
            .runtime_register_offset = capabilities.runtime_register_offset,
            .command_ring_address = plan.ring_plan.command_ring_address,
            .event_ring_address = plan.ring_plan.event_ring_address,
            .device_context_base_address = plan.arena.device_contexts_address,
            .input_context_address = plan.arena.input_context_address,
            .transfer_ring_address = plan.arena.interruptTransferRingAddress(report.slot_id) catch return null,
            .event_ring_segment_table_address = plan.event_ring_segment_table_address,
            .context_size = capabilities.context_size,
            .device_context_bytes = std.math.cast(u32, plan.arena.device_contexts_bytes) orelse
                return null,
            .input_context_bytes = plan.arena.input_context_bytes,
            .transfer_ring_trbs = plan.arena.interrupt_transfer_ring_trbs,
            .event_ring_segment_table_entries = plan.event_ring_segment_table_entries,
            .command_doorbells = saturatingU32(command_completion_count),
            .transfer_doorbells = saturatingU32(control_doorbells +| interrupt_report_submission_count),
            .device_context_writes = 2,
            .endpoint_context_writes = saturatingU32(configure_endpoint_count),
            .event_ring_segment_table_writes = plan.event_ring_segment_table_entries,
            .event_ring_dequeue_count = saturatingU32(event_count),
            .interrupt_events = delivered_events_u32,
            .interrupter_id = INTERRUPT_VECTOR,
            .enabled_device_slots = active_enabled_slots,
            .max_ports = capabilities.max_ports,
            .hardware_input = .{
                .source = .hardware_event_ring,
                .controller_event_trbs = delivered_events_u32,
                .event_ring_dma_writes = delivered_events_u32,
                .device_context_reads_by_controller = 1,
                .endpoint_context_reads_by_controller = 1,
                .interrupt_assertions = saturatingU32(@atomicLoad(u64, &interrupt_count, .monotonic)),
                .port_status_change_events = saturatingU32(port_status_change_count),
                .input_report_dma_bytes = input_report_dma_bytes,
            },
        },
    };
}

fn saturatingU32(value: u64) u32 {
    return @intCast(@min(value, std.math.maxInt(u32)));
}

pub fn deviceDescriptorForPort(port_id: u8) ?xhci.UsbDeviceDescriptor {
    if (!controllerActive()) return null;
    const capabilities = active_capabilities orelse return null;
    if (port_id == 0 or port_id > capabilities.max_ports) return null;
    return if (ports[port_id].retiring) null else ports[port_id].device_descriptor;
}

pub fn configurationDescriptorForPort(port_id: u8) ?xhci.UsbConfigurationDescriptor {
    if (!controllerActive()) return null;
    const capabilities = active_capabilities orelse return null;
    if (port_id == 0 or port_id > capabilities.max_ports) return null;
    return if (ports[port_id].retiring) null else ports[port_id].configuration_descriptor;
}

pub fn bootKeyboardConfigurationForPort(port_id: u8) ?xhci.UsbBootKeyboardConfiguration {
    if (!controllerActive()) return null;
    const capabilities = active_capabilities orelse return null;
    if (port_id == 0 or port_id > capabilities.max_ports) return null;
    return if (ports[port_id].retiring) null else ports[port_id].boot_keyboard;
}

pub fn portConfigured(port_id: u8) bool {
    if (!controllerActive()) return false;
    const capabilities = active_capabilities orelse return false;
    if (port_id == 0 or port_id > capabilities.max_ports) return false;
    return !ports[port_id].retiring and ports[port_id].endpoint_configured;
}

pub fn handledInterruptCount() u64 {
    return @atomicLoad(u64, &interrupt_count, .monotonic);
}

fn clearPortDescriptorState(state: *PortRuntimeState) void {
    if (state.endpoint_configured and !state.retiring) keyboard_continuity_epoch +|= 1;
    state.descriptor_prefix_valid = false;
    state.device_descriptor = null;
    state.configuration_descriptor_header = null;
    state.configuration_descriptor = null;
    state.boot_keyboard = null;
    state.configuration_set = false;
    state.boot_protocol_set = false;
    state.endpoint_configured = false;
    state.endpoint_zero_max_packet_size = 0;
    state.pending_endpoint_zero_max_packet_size = 0;
    state.interrupt_report_trb_address = 0;
    state.endpoint_state.failed_mask = 0;
    state.endpoint_state.stopped_mask = 0;
}

fn scheduleUnarmedInterruptReports() void {
    const capabilities = active_capabilities orelse return;
    var reserved = outstanding_interrupt_reports;
    var existing_port_id: u16 = 1;
    while (existing_port_id <= capabilities.max_ports) : (existing_port_id += 1) {
        if (ports[existing_port_id].action == .post_interrupt_report) reserved += 1;
    }
    var port_id: u16 = 1;
    while (port_id <= capabilities.max_ports) : (port_id += 1) {
        const state = &ports[port_id];
        if (state.retiring or !state.connected or !state.enabled or !state.addressed or
            !state.configuration_set or !state.boot_protocol_set or
            !state.endpoint_configured or state.interrupt_report_trb_address != 0 or
            state.action != .none)
        {
            continue;
        }
        if (!keyboardReports().hasCapacity(reserved + 1)) return;
        state.action = .post_interrupt_report;
        reserved += 1;
    }
}

fn beginPortRetirement(port_id: u8, state: *PortRuntimeState) void {
    keyboardReports().clearPort(port_id);
    if (!state.retiring) {
        if (state.endpoint_configured) keyboard_continuity_epoch +|= 1;
        state.retiring = true;
        state.reset_deadline = tsc_clock.afterMilliseconds(RETIREMENT_TIMEOUT_MILLISECONDS);
    }
    state.action = .retire_slot;
}

fn handlePortStatusChange(event: xhci.Event, reader: anytype) Error!void {
    const capabilities = active_capabilities orelse return error.InvalidPortStatus;
    const protocols = active_protocols orelse return error.MissingSupportedProtocols;
    if (!event.succeeded() or event.port_id == 0 or event.port_id > capabilities.max_ports) {
        return error.InvalidPortStatus;
    }
    const protocol = protocols.forPort(event.port_id) orelse return error.MissingPortProtocol;
    const register_offset = try xhci.portRegisterOffset(capabilities, event.port_id);
    const raw_status = reader.readReg32(register_offset);
    const status = xhci.decodePortStatus(raw_status);
    if (status.over_current) return error.InvalidPortStatus;
    // A previously acknowledged change can have another queued notification.
    if (status.change_bits == 0) return;

    const state = &ports[event.port_id];
    // CSC can cover both removal and insertion before software reads PORTSC.
    const changed_lifetime = !status.connected or
        ((status.change_bits & 1) != 0 and state.connected and
            (state.slot_id != 0 or commandTargets(event.port_id, .enable_slot)));
    if (state.enabled and !status.enabled) keyboard_continuity_epoch +|= 1;
    state.connected = status.connected;
    state.enabled = status.enabled;
    if (changed_lifetime) {
        reader.writeReg32(register_offset, xhci.portStatusAcknowledge(raw_status));
        keyboardReports().clearPort(event.port_id);
        if (state.slot_id != 0 or commandTargets(event.port_id, .enable_slot)) {
            beginPortRetirement(event.port_id, state);
        }
        if (state.retiring) {
            // Keep slot, endpoint and TD ownership until Stop/Disable barriers.
            if (status.connected) state.speed_id = status.speed;
            state.action = .retire_slot;
        } else {
            state.addressed = false;
            clearPortDescriptorState(state);
            state.speed_id = 0;
            state.reset_deadline = null;
            state.action = .none;
        }
        scheduleUnarmedInterruptReports();
        return;
    }
    if (state.retiring) {
        reader.writeReg32(register_offset, xhci.portStatusAcknowledge(raw_status));
        // Remember the replacement attachment, but never enumerate the old slot.
        state.speed_id = status.speed;
        state.action = .retire_slot;
        return;
    }
    if (!status.powered) return error.InvalidPortStatus;
    if (status.enabled) {
        const initial_max_packet_size = try xhci.endpointZeroMaxPacketSize(protocol, status.speed);
        reader.writeReg32(register_offset, xhci.portStatusAcknowledge(raw_status));
        state.speed_id = status.speed;
        state.reset_deadline = null;
        if (state.slot_id == 0 and !commandTargets(event.port_id, .enable_slot)) {
            state.action = .enable_slot;
        } else if (state.slot_id != 0 and !state.addressed and
            !commandTargets(event.port_id, .address_device))
        {
            state.action = .address_device;
        } else if (state.addressed and !state.descriptor_prefix_valid and
            state.pending_endpoint_zero_max_packet_size == 0 and
            !transferTargets(event.port_id))
        {
            if (state.endpoint_zero_max_packet_size == 0) {
                state.endpoint_zero_max_packet_size = initial_max_packet_size;
            }
            state.action = .read_device_descriptor_prefix;
        } else if (state.addressed and state.descriptor_prefix_valid and
            state.device_descriptor == null and
            state.pending_endpoint_zero_max_packet_size == 0 and
            !transferTargets(event.port_id))
        {
            state.action = .read_device_descriptor;
        } else if (state.addressed and state.device_descriptor != null and
            state.configuration_descriptor_header == null and
            !transferTargets(event.port_id))
        {
            state.action = .read_configuration_descriptor_header;
        } else if (state.addressed and state.configuration_descriptor_header != null and
            state.configuration_descriptor == null and
            !transferTargets(event.port_id))
        {
            state.action = .read_configuration_descriptor;
        } else if (state.addressed and state.configuration_descriptor != null and
            state.boot_keyboard != null and !state.configuration_set and
            !transferTargets(event.port_id))
        {
            state.action = .set_configuration;
        } else if (state.addressed and state.configuration_set and
            !state.boot_protocol_set and
            !transferTargets(event.port_id))
        {
            state.action = .set_boot_protocol;
        } else if (state.addressed and state.configuration_set and state.boot_protocol_set and
            !state.endpoint_configured and
            !commandTargets(event.port_id, .configure_endpoint))
        {
            state.action = .configure_endpoint;
        }
        return;
    }
    if ((status.change_bits & PORT_RESET_COMPLETION_CHANGE_MASK) != 0) {
        reader.writeReg32(register_offset, xhci.portStatusAcknowledge(raw_status));
        return error.InvalidPortStatus;
    }
    if (status.reset_active) {
        reader.writeReg32(register_offset, xhci.portStatusAcknowledge(raw_status));
        if (state.reset_deadline == null) {
            state.reset_deadline = tsc_clock.afterMilliseconds(PORT_RESET_TIMEOUT_MILLISECONDS);
        }
        return;
    }
    if (protocol.kind == .usb3 and !status.cold_attach) return error.InvalidPortStatus;

    reader.writeReg32(register_offset, xhci.portResetWrite(raw_status, protocol));
    state.reset_deadline = tsc_clock.afterMilliseconds(PORT_RESET_TIMEOUT_MILLISECONDS);
}

fn handleCommandCompletion(event: xhci.Event, reader: anytype) Error!void {
    const command = outstanding_command orelse return error.CommandRingStateInvalid;
    if (command.state_error_seen or event.parameter != command.trb_address) {
        return error.CommandRingStateInvalid;
    }
    const capabilities = active_capabilities orelse return error.CommandRingStateInvalid;
    const state = &ports[command.port_id];
    if (!event.succeeded()) {
        if (state.retiring and command.kind == .stop_endpoint and event.completion_code == 19 and
            command.slot_id != 0 and event.slot_id == command.slot_id and state.slot_id == command.slot_id and
            !command.stopped_event_seen)
        {
            const bit = try failedEndpointBit(state, command.endpoint_id);
            if ((state.endpoint_state.failed_mask & bit) != 0) {
                state.action = .retire_slot;
                outstanding_command = null;
                return;
            }
            if (!endpointTransferOwned(command.port_id, state, command.endpoint_id)) {
                return error.CommandRingStateInvalid;
            }
            // This completed Stop may precede its failed TD event. Keep its
            // original deadline and TD ownership; only exact CC4 permits Reset.
            outstanding_command.?.state_error_seen = true;
            return;
        }
        // 1.2c 4.6.5: USB Transaction Error leaves Address Device incomplete.
        // Physical detach can cause this exact owned failure; no TD was posted.
        if (command.kind != .address_device or event.completion_code != 4 or
            command.slot_id == 0 or event.slot_id != command.slot_id or state.slot_id != command.slot_id or
            state.addressed or state.endpoint_configured or state.interrupt_report_trb_address != 0 or
            transferTargets(command.port_id))
        {
            return error.CommandRingStateInvalid;
        }
        try authenticatePortRetirement(command.port_id, state, reader);
        state.action = .retire_slot;
        outstanding_command = null;
        return;
    }
    switch (command.kind) {
        .enable_slot => {
            if (event.slot_id == 0 or event.slot_id > active_enabled_slots or state.slot_id != 0) {
                return error.InvalidDeviceSlot;
            }
            if (slot_to_port[event.slot_id] != 0) return error.InvalidDeviceSlot;
            var port_id: u16 = 1;
            while (port_id <= capabilities.max_ports) : (port_id += 1) {
                if (ports[port_id].slot_id == event.slot_id) return error.InvalidDeviceSlot;
            }
            try clearDeviceContext(event.slot_id);
            try resetSlotTransferRings(event.slot_id);
            try writeDcbaaSlot(event.slot_id, try active_dma_plan.?.arena.deviceContextAddress(event.slot_id));
            slot_to_port[event.slot_id] = command.port_id;
            state.slot_id = event.slot_id;
            state.addressed = false;
            clearPortDescriptorState(state);
            state.action = if (state.retiring) .retire_slot else if (state.connected and state.enabled) .address_device else .disable_slot;
        },
        .address_device => {
            if (command.slot_id == 0 or event.slot_id != command.slot_id or
                state.slot_id != command.slot_id or state.addressed)
            {
                return error.InvalidDeviceSlot;
            }
            state.addressed = true;
            state.endpoint_state.stopped_mask &= ~@as(u2, 1);
            if (state.addressed and state.endpoint_zero_max_packet_size == 0) {
                return error.InvalidInputContext;
            }
            state.action = if (state.retiring) .retire_slot else .read_device_descriptor_prefix;
        },
        .configure_endpoint => {
            if (command.slot_id == 0 or event.slot_id != command.slot_id or
                state.slot_id != command.slot_id or !state.addressed or
                state.configuration_descriptor == null or state.boot_keyboard == null or
                !state.configuration_set or !state.boot_protocol_set or
                state.endpoint_configured)
            {
                return error.InvalidDeviceSlot;
            }
            state.endpoint_configured = true;
            state.endpoint_state.stopped_mask &= ~@as(u2, 2);
            state.action = .post_interrupt_report;
            configure_endpoint_count +%= 1;
        },
        .evaluate_context => {
            if (command.slot_id == 0 or event.slot_id != command.slot_id or
                state.slot_id != command.slot_id or !state.addressed or
                state.pending_endpoint_zero_max_packet_size == 0 or
                state.descriptor_prefix_valid or state.device_descriptor != null)
            {
                return error.InvalidDeviceSlot;
            }
            state.endpoint_zero_max_packet_size = state.pending_endpoint_zero_max_packet_size;
            state.pending_endpoint_zero_max_packet_size = 0;
            state.descriptor_prefix_valid = true;
            state.action = .read_device_descriptor;
        },
        .reset_endpoint => {
            const bit = try failedEndpointBit(state, command.endpoint_id);
            if (!state.retiring or command.slot_id == 0 or event.slot_id != command.slot_id or
                state.slot_id != command.slot_id or (state.endpoint_state.failed_mask & bit) == 0 or
                try outputEndpointState(state.slot_id, command.endpoint_id) != .stopped)
            {
                return error.CommandRingStateInvalid;
            }
            if (command.endpoint_id == xhci.ENDPOINT_ZERO_DCI) {
                const transfer = outstanding_transfer orelse return error.TrbRingStateInvalid;
                if (transfer.port_id != command.port_id or transfer.slot_id != state.slot_id) {
                    return error.TrbRingStateInvalid;
                }
                outstanding_transfer = null;
            } else {
                try retireInterruptReport(state);
            }
            state.endpoint_state.failed_mask &= ~bit;
            state.endpoint_state.stopped_mask |= bit;
            state.action = .retire_slot;
        },
        .stop_endpoint => {
            if (!state.retiring or command.slot_id == 0 or event.slot_id != command.slot_id or
                state.slot_id != command.slot_id or !command.stopped_event_seen or
                try outputEndpointState(state.slot_id, command.endpoint_id) != .stopped)
            {
                return error.CommandRingStateInvalid;
            }
            state.endpoint_state.stopped_mask |= try failedEndpointBit(state, command.endpoint_id);
            state.action = .retire_slot;
        },
        .disable_slot => {
            if (command.slot_id == 0 or event.slot_id != command.slot_id or
                state.slot_id != command.slot_id)
            {
                return error.InvalidDeviceSlot;
            }
            try writeDcbaaSlot(command.slot_id, 0);
            try clearDeviceContext(command.slot_id);
            slot_to_port[command.slot_id] = 0;
            state.slot_id = 0;
            state.addressed = false;
            clearPortDescriptorState(state);
            state.retiring = false;
            state.reset_deadline = null;
            state.action = if (state.connected and state.enabled) .enable_slot else if (state.connected) .reset_port else .none;
        },
    }
    if (state.retiring) state.action = .retire_slot;
    outstanding_command = null;
}

fn handleControlTransferCompletion(event: xhci.Event, reader: anytype) Error!void {
    if (event.stoppedCompletion() != null) return handleStoppedTransferCompletion(event);
    const transfer = outstanding_transfer orelse return error.TrbRingStateInvalid;
    if (event.completion_code == 4) {
        if (event.endpoint_id != xhci.ENDPOINT_ZERO_DCI or transfer.port_id == 0 or
            transfer.port_id >= ports.len or ports[transfer.port_id].slot_id != transfer.slot_id)
        {
            return error.TrbRingStateInvalid;
        }
        const addresses = try controlTransferTrbAddresses(transfer);
        const count: usize = if (transfer.kind == .set_configuration or transfer.kind == .set_boot_protocol) 2 else 3;
        try xhci.validateFailedTransferEvent(event, addresses[0..count], transfer.slot_id, xhci.ENDPOINT_ZERO_DCI);
        const stage_bytes: u32 = if (event.parameter == addresses[0]) 0 else if (event.parameter == addresses[count - 1]) 8 else switch (transfer.kind) {
            .device_descriptor_prefix => xhci.USB_DEVICE_DESCRIPTOR_PREFIX_BYTES,
            .device_descriptor => xhci.USB_DEVICE_DESCRIPTOR_BYTES,
            .configuration_descriptor_header => xhci.USB_CONFIGURATION_DESCRIPTOR_BYTES,
            .configuration_descriptor => (ports[transfer.port_id].configuration_descriptor_header orelse
                return error.InvalidDeviceSlot).total_length,
            .set_configuration, .set_boot_protocol => return error.TrbRingStateInvalid,
        };
        if (event.transfer_length > stage_bytes) return error.TrbRingStateInvalid;
        try handleDetachedTransferFailure(event, transfer.port_id, addresses[0..count], reader);
        return;
    }
    if (!event.succeeded() or event.parameter != transfer.status_trb_address or
        event.slot_id != transfer.slot_id or
        event.endpoint_id != xhci.ENDPOINT_ZERO_DCI or
        event.event_data or event.transfer_length != 0)
    {
        return error.TrbRingStateInvalid;
    }
    const state = &ports[transfer.port_id];
    if (state.retiring) {
        if ((state.endpoint_state.failed_mask & 1) != 0) return error.TrbRingStateInvalid;
        if (state.slot_id != transfer.slot_id) return error.InvalidDeviceSlot;
        outstanding_transfer = null;
        state.action = .retire_slot;
        return;
    }
    const protocols = active_protocols orelse return error.MissingSupportedProtocols;
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    if (!state.connected or !state.enabled or !state.addressed or
        state.slot_id != transfer.slot_id)
    {
        return error.InvalidDeviceSlot;
    }
    const source_alias = try active_dma_memory.aliasFor(
        plan.arena.enumeration_buffer_address,
        @intCast(plan.arena.enumeration_buffer_bytes),
    );
    const source: [*]volatile u8 = @ptrFromInt(source_alias);
    const first_byte: *const u8 = @ptrFromInt(source_alias);
    _ = @atomicLoad(u8, first_byte, .acquire);
    const protocol = protocols.forPort(transfer.port_id) orelse
        return error.MissingPortProtocol;
    switch (transfer.kind) {
        .device_descriptor_prefix => {
            if (state.descriptor_prefix_valid or state.device_descriptor != null or
                state.pending_endpoint_zero_max_packet_size != 0)
            {
                return error.InvalidDeviceSlot;
            }
            var descriptor_prefix: [xhci.USB_DEVICE_DESCRIPTOR_PREFIX_BYTES]u8 = undefined;
            for (&descriptor_prefix, 0..) |*byte, index| byte.* = source[index];
            const max_packet_size = try xhci.deviceDescriptorEndpointZeroMaxPacketSize(
                protocol,
                state.speed_id,
                &descriptor_prefix,
            );
            if (max_packet_size != state.endpoint_zero_max_packet_size) {
                state.pending_endpoint_zero_max_packet_size = max_packet_size;
                state.action = .evaluate_endpoint_zero;
            } else {
                state.descriptor_prefix_valid = true;
                state.action = .read_device_descriptor;
            }
            descriptor_prefix_count +%= 1;
        },
        .device_descriptor => {
            if (!state.descriptor_prefix_valid or state.device_descriptor != null or
                state.pending_endpoint_zero_max_packet_size != 0)
            {
                return error.InvalidDeviceSlot;
            }
            var descriptor_bytes: [xhci.USB_DEVICE_DESCRIPTOR_BYTES]u8 = undefined;
            for (&descriptor_bytes, 0..) |*byte, index| byte.* = source[index];
            const descriptor = try xhci.parseUsbDeviceDescriptor(
                protocol,
                state.speed_id,
                &descriptor_bytes,
            );
            if (descriptor.endpoint_zero_max_packet_size !=
                state.endpoint_zero_max_packet_size)
            {
                return error.InvalidUsbDescriptor;
            }
            state.device_descriptor = descriptor;
            state.action = .read_configuration_descriptor_header;
            device_descriptor_count +%= 1;
        },
        .configuration_descriptor_header => {
            if (state.device_descriptor == null or
                state.configuration_descriptor_header != null or
                state.configuration_descriptor != null)
            {
                return error.InvalidDeviceSlot;
            }
            var descriptor_bytes: [xhci.USB_CONFIGURATION_DESCRIPTOR_BYTES]u8 = undefined;
            for (&descriptor_bytes, 0..) |*byte, index| byte.* = source[index];
            const descriptor = try xhci.parseUsbConfigurationDescriptorHeader(
                protocol,
                &descriptor_bytes,
            );
            if (descriptor.total_length > plan.arena.enumeration_buffer_bytes) {
                return error.InvalidUsbDescriptor;
            }
            state.configuration_descriptor_header = descriptor;
            state.action = .read_configuration_descriptor;
            configuration_descriptor_header_count +%= 1;
        },
        .configuration_descriptor => {
            const expected = state.configuration_descriptor_header orelse
                return error.InvalidDeviceSlot;
            if (state.device_descriptor == null or state.configuration_descriptor != null) {
                return error.InvalidDeviceSlot;
            }
            const selection = try parseConfigurationDescriptorFromDma(
                protocol,
                state.speed_id,
                source,
                expected.total_length,
            );
            if (!std.meta.eql(expected, selection.configuration)) {
                return error.InvalidUsbDescriptor;
            }
            state.configuration_descriptor = selection.configuration;
            state.boot_keyboard = selection.keyboard;
            state.action = .set_configuration;
            configuration_descriptor_count +%= 1;
        },
        .set_configuration => {
            if (state.configuration_descriptor == null or state.boot_keyboard == null or
                state.configuration_set or state.boot_protocol_set or
                state.endpoint_configured)
            {
                return error.InvalidDeviceSlot;
            }
            state.configuration_set = true;
            state.action = .set_boot_protocol;
            set_configuration_count +%= 1;
        },
        .set_boot_protocol => {
            if (state.configuration_descriptor == null or state.boot_keyboard == null or
                !state.configuration_set or state.boot_protocol_set or
                state.endpoint_configured)
            {
                return error.InvalidDeviceSlot;
            }
            state.boot_protocol_set = true;
            state.action = .configure_endpoint;
            set_boot_protocol_count +%= 1;
        },
    }
    outstanding_transfer = null;
}

fn handleInterruptTransferCompletion(event: xhci.Event, reader: anytype) Error!void {
    if (event.stoppedCompletion() != null) return handleStoppedTransferCompletion(event);
    if (event.slot_id == 0 or event.slot_id > active_enabled_slots) {
        return error.InvalidDeviceSlot;
    }
    const port_id = slot_to_port[event.slot_id];
    const capabilities = active_capabilities orelse return error.TrbRingStateInvalid;
    if (port_id == 0 or port_id > capabilities.max_ports) return error.InvalidDeviceSlot;
    const state = &ports[port_id];
    if (event.completion_code == 4) {
        if (state.interrupt_report_trb_address == 0 or outstanding_interrupt_reports == 0 or
            event.transfer_length > xhci.HID_BOOT_KEYBOARD_REPORT_BYTES)
        {
            return error.TrbRingStateInvalid;
        }
        try handleDetachedTransferFailure(event, port_id, &.{state.interrupt_report_trb_address}, reader);
        return;
    }
    if (state.retiring) {
        if ((state.endpoint_state.failed_mask & 2) != 0) return error.TrbRingStateInvalid;
        const keyboard = state.boot_keyboard orelse return error.InvalidDeviceSlot;
        try xhci.validateInterruptTransferEvent(event, state.interrupt_report_trb_address, state.slot_id, keyboard.device_context_index);
        try retireInterruptReport(state);
        return;
    }
    const descriptor = state.device_descriptor orelse return error.InvalidDeviceSlot;
    const keyboard = state.boot_keyboard orelse return error.InvalidDeviceSlot;
    if (!state.connected or !state.enabled or !state.addressed or
        !state.configuration_set or !state.boot_protocol_set or
        !state.endpoint_configured or state.slot_id != event.slot_id)
    {
        return error.InvalidDeviceSlot;
    }
    try xhci.validateInterruptTransferEvent(
        event,
        state.interrupt_report_trb_address,
        state.slot_id,
        keyboard.device_context_index,
    );

    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    if (outstanding_interrupt_reports == 0) return error.TrbRingStateInvalid;
    outstanding_interrupt_reports -= 1;
    const buffer_address = try plan.arena.interruptReportBufferAddress(state.slot_id);
    const buffer_alias = try active_dma_memory.aliasFor(
        buffer_address,
        xhci.HID_BOOT_KEYBOARD_REPORT_BYTES,
    );
    const source: [*]volatile u8 = @ptrFromInt(buffer_alias);
    const first_byte: *const u8 = @ptrFromInt(buffer_alias);
    _ = @atomicLoad(u8, first_byte, .acquire);
    var report: [xhci.HID_BOOT_KEYBOARD_REPORT_BYTES]u8 = undefined;
    for (&report, 0..) |*byte, index| byte.* = source[index];
    _ = try keyboardReports().publish(port_id, state.slot_id, keyboard, descriptor, &report);

    state.interrupt_report_trb_address = 0;
    state.action = if (keyboardReports().hasCapacity(outstanding_interrupt_reports + 1))
        .post_interrupt_report
    else
        .none;
    keyboard_report_count +%= 1;
}

fn controlTransferTrbAddresses(transfer: OutstandingTransfer) Error![3]u64 {
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    const ring = try plan.arena.controlTransferRingAddress(transfer.slot_id);
    const usable_trbs = plan.arena.control_transfer_ring_trbs - 1;
    if (transfer.status_trb_address < ring or (transfer.status_trb_address - ring) % xhci.TRB_BYTES != 0) {
        return error.TrbRingStateInvalid;
    }
    var index = (transfer.status_trb_address - ring) / xhci.TRB_BYTES;
    if (index >= usable_trbs) return error.TrbRingStateInvalid;
    var addresses: [3]u64 = undefined;
    for (&addresses) |*address| {
        address.* = ring + index * xhci.TRB_BYTES;
        index = if (index == 0) usable_trbs - 1 else index - 1;
    }
    return addresses;
}

fn failedEndpointBit(state: *const PortRuntimeState, endpoint_id: u5) Error!u2 {
    if (endpoint_id == xhci.ENDPOINT_ZERO_DCI) return 1;
    const keyboard = state.boot_keyboard orelse return error.InvalidDeviceSlot;
    if (!state.endpoint_configured or endpoint_id != keyboard.device_context_index) return error.InvalidDeviceSlot;
    return 2;
}

fn authenticatePortRetirement(port_id: u8, state: *PortRuntimeState, reader: anytype) Error!void {
    if (!state.retiring) {
        const capabilities = active_capabilities orelse return error.InvalidPortStatus;
        const register_offset = try xhci.portRegisterOffset(capabilities, port_id);
        const raw_status = reader.readReg32(register_offset);
        const status = xhci.decodePortStatus(raw_status);
        if (status.over_current or (status.connected and (status.change_bits & 1) == 0)) {
            return error.TrbRingStateInvalid;
        }
        state.connected = status.connected;
        state.enabled = status.enabled;
        if (status.connected) state.speed_id = status.speed;
        reader.writeReg32(register_offset, xhci.portStatusAcknowledge(raw_status));
        beginPortRetirement(port_id, state);
    }
}

fn handleDetachedTransferFailure(event: xhci.Event, port_id: u8, addresses: []const u64, reader: anytype) Error!void {
    if (port_id == 0 or port_id >= ports.len) return error.InvalidDeviceSlot;
    const state = &ports[port_id];
    const bit = try failedEndpointBit(state, event.endpoint_id);
    try xhci.validateFailedTransferEvent(event, addresses, state.slot_id, event.endpoint_id);
    if ((state.endpoint_state.failed_mask & bit) != 0) return error.TrbRingStateInvalid;
    try authenticatePortRetirement(port_id, state, reader);
    // Retain the TD and its reservation until the Reset completion barrier.
    state.endpoint_state.failed_mask |= bit;
    if (outstanding_command) |command| {
        if (command.kind == .stop_endpoint and command.state_error_seen and
            command.port_id == port_id and command.slot_id == state.slot_id and
            command.endpoint_id == event.endpoint_id)
        {
            outstanding_command = null;
        }
    }
    state.action = .retire_slot;
}

// xHCI 1.2c 4.6.9 orders the forced stopped Transfer Event before the
// command completion on our single primary interrupter, even for an empty ring.
fn handleStoppedTransferCompletion(event: xhci.Event) Error!void {
    const command = if (outstanding_command) |*command| command else return error.CommandRingStateInvalid;
    if (command.kind != .stop_endpoint or command.stopped_event_seen or command.state_error_seen or
        command.port_id == 0 or command.port_id >= ports.len)
    {
        return error.CommandRingStateInvalid;
    }
    const state = &ports[command.port_id];
    if (!state.retiring or state.slot_id != command.slot_id) return error.InvalidDeviceSlot;
    if ((state.endpoint_state.failed_mask & try failedEndpointBit(state, command.endpoint_id)) != 0) {
        return error.CommandRingStateInvalid;
    }
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    const control = command.endpoint_id == xhci.ENDPOINT_ZERO_DCI;
    if (!control) {
        const keyboard = state.boot_keyboard orelse return error.InvalidDeviceSlot;
        if (!state.endpoint_configured or command.endpoint_id != keyboard.device_context_index) {
            return error.InvalidDeviceSlot;
        }
    }
    _ = try xhci.validateStoppedTransferEvent(event, if (control) try plan.arena.controlTransferRingAddress(state.slot_id) else try plan.arena.interruptTransferRingAddress(state.slot_id), if (control) plan.arena.control_transfer_ring_trbs else plan.arena.interrupt_transfer_ring_trbs, state.slot_id, command.endpoint_id);
    if (control) {
        if (outstanding_transfer) |transfer| {
            if (transfer.port_id == command.port_id) {
                if (transfer.slot_id != state.slot_id) return error.TrbRingStateInvalid;
                outstanding_transfer = null;
            }
        }
    } else if (state.interrupt_report_trb_address != 0) {
        try retireInterruptReport(state);
    }
    command.stopped_event_seen = true;
}

fn retireInterruptReport(state: *PortRuntimeState) Error!void {
    if (state.interrupt_report_trb_address == 0 or outstanding_interrupt_reports == 0) {
        return error.TrbRingStateInvalid;
    }
    outstanding_interrupt_reports -= 1;
    state.interrupt_report_trb_address = 0;
    state.action = .retire_slot;
    scheduleUnarmedInterruptReports();
}

fn outputEndpointState(slot_id: u8, endpoint_id: u5) Error!xhci.EndpointState {
    if (endpoint_id == 0) return error.InvalidDeviceSlot;
    const capabilities = active_capabilities orelse return error.CommandRingStateInvalid;
    const plan = active_dma_plan orelse return error.CommandRingStateInvalid;
    const context_address = try plan.arena.deviceContextAddress(slot_id);
    const offset = @as(u64, endpoint_id) * capabilities.context_size.byteCount();
    const address = try active_dma_memory.aliasFor(context_address + offset, @sizeOf(u32));
    const word: *const u32 = @ptrFromInt(address);
    return xhci.decodeEndpointState(@atomicLoad(u32, word, .acquire));
}

const RetirementCommand = struct {
    kind: xhci.CommandKind,
    endpoint_id: u5 = 0,
};

fn endpointTransferOwned(port_id: u8, state: *const PortRuntimeState, endpoint_id: u5) bool {
    if (endpoint_id == xhci.ENDPOINT_ZERO_DCI) {
        const transfer = outstanding_transfer orelse return false;
        return transfer.port_id == port_id and transfer.slot_id == state.slot_id;
    }
    const keyboard = state.boot_keyboard orelse return false;
    return state.endpoint_configured and endpoint_id == keyboard.device_context_index and
        state.interrupt_report_trb_address != 0 and outstanding_interrupt_reports != 0;
}

fn retirementEndpointCommand(port_id: u8, state: *const PortRuntimeState, endpoint_id: u5, bit: u2) Error!RetirementCommand {
    if ((state.endpoint_state.failed_mask & bit) != 0) {
        return .{ .kind = .reset_endpoint, .endpoint_id = endpoint_id };
    }
    // A snapshot can expose unsupported state, but cannot authenticate Reset.
    // Halted with an owned TD may precede its event; Stop/19 stays bounded.
    switch (try outputEndpointState(state.slot_id, endpoint_id)) {
        .error_state => return error.CommandRingStateInvalid,
        .halted => if (!endpointTransferOwned(port_id, state, endpoint_id)) return error.CommandRingStateInvalid,
        .disabled, .running, .stopped => {},
    }
    return .{ .kind = .stop_endpoint, .endpoint_id = endpoint_id };
}

fn nextRetirementCommand(state: *const PortRuntimeState) Error!RetirementCommand {
    if (!state.retiring or state.slot_id == 0) return error.InvalidDeviceSlot;
    // 1.2c 4.8.3: Output EP State may lag errors and doorbells. Use the
    // transitions established by our commands/events, never an instant snapshot.
    if (state.addressed and (state.endpoint_state.stopped_mask & 1) == 0) {
        return retirementEndpointCommand(slot_to_port[state.slot_id], state, xhci.ENDPOINT_ZERO_DCI, 1);
    }
    if (transferTargets(slot_to_port[state.slot_id])) return error.TrbRingStateInvalid;
    if (state.endpoint_configured and (state.endpoint_state.stopped_mask & 2) == 0) {
        const keyboard = state.boot_keyboard orelse return error.InvalidDeviceSlot;
        return retirementEndpointCommand(slot_to_port[state.slot_id], state, keyboard.device_context_index, 2);
    }
    if (state.interrupt_report_trb_address != 0 or state.endpoint_state.failed_mask != 0) {
        return error.TrbRingStateInvalid;
    }
    // A failed Address Device has no posted TD, and 4.6.5 explicitly permits
    // disabling its Default slot directly, including an idle Running EP0.
    return .{ .kind = .disable_slot };
}

fn parseConfigurationDescriptorFromDma(
    protocol: xhci.PortProtocol,
    speed_id: u4,
    source: [*]volatile u8,
    total_length: u16,
) Error!xhci.UsbBootKeyboardSelection {
    if (total_length < xhci.USB_CONFIGURATION_DESCRIPTOR_BYTES or
        total_length > xhci.USB_ENUMERATION_BUFFER_BYTES)
    {
        return error.InvalidUsbDescriptor;
    }
    var parser = xhci.ConfigurationDescriptorParser.initForPort(protocol, speed_id);
    var descriptor_storage: [std.math.maxInt(u8)]u8 = undefined;
    var offset: usize = 0;
    while (offset < total_length) {
        if (offset + 2 > total_length) return error.InvalidUsbDescriptor;
        const descriptor_length: usize = source[offset];
        const end = std.math.add(usize, offset, descriptor_length) catch
            return error.InvalidUsbDescriptor;
        if (descriptor_length < 2 or end > total_length) {
            return error.InvalidUsbDescriptor;
        }
        for (descriptor_storage[0..descriptor_length], 0..) |*byte, index| {
            byte.* = source[offset + index];
        }
        try parser.consume(descriptor_storage[0..descriptor_length]);
        offset = end;
    }
    return parser.finishBootKeyboard(total_length);
}

fn commandTargets(port_id: u8, kind: xhci.CommandKind) bool {
    const command = outstanding_command orelse return false;
    return command.port_id == port_id and command.kind == kind;
}

fn transferTargets(port_id: u8) bool {
    const transfer = outstanding_transfer orelse return false;
    return transfer.port_id == port_id;
}

fn controlTransferTimedOut() bool {
    const transfer = outstanding_transfer orelse return false;
    return !ports[transfer.port_id].retiring and transfer.deadline.expired();
}

const PortDeadlineKind = enum { reset, retirement };

fn expiredPortDeadline(state: *const PortRuntimeState) ?PortDeadlineKind {
    const deadline = state.reset_deadline orelse return null;
    if (!deadline.expired()) return null;
    return if (state.retiring) .retirement else .reset;
}

fn commandTimedOut() bool {
    const command = outstanding_command orelse return false;
    return command.deadline.expired();
}

fn lifecycleTimedOut() bool {
    if (commandTimedOut()) {
        containFailure("ZIGOS:XHCI:HW:COMMAND_TIMEOUT_CONTAINED\n");
        return true;
    }
    if (controlTransferTimedOut()) {
        containFailure("ZIGOS:XHCI:HW:TRANSFER_TIMEOUT_CONTAINED\n");
        return true;
    }
    const capabilities = active_capabilities orelse return false;
    var port_id: u16 = 1;
    while (port_id <= capabilities.max_ports) : (port_id += 1) {
        if (expiredPortDeadline(&ports[port_id])) |kind| {
            containFailure(if (kind == .retirement)
                "ZIGOS:XHCI:HW:RETIREMENT_TIMEOUT_CONTAINED\n"
            else
                "ZIGOS:XHCI:HW:PORT_RESET_TIMEOUT_CONTAINED\n");
            return true;
        }
    }
    return false;
}

fn submitNextPortAction(reader: anytype) Error!void {
    if (outstanding_command != null) return;
    const capabilities = active_capabilities orelse return error.CommandRingStateInvalid;
    const protocols = active_protocols orelse return error.MissingSupportedProtocols;
    const plan = active_dma_plan orelse return error.CommandRingStateInvalid;
    var inspected: u16 = 0;
    while (inspected < capabilities.max_ports) : (inspected += 1) {
        const port_id: u8 = @intCast(next_port_scan);
        next_port_scan = if (next_port_scan >= capabilities.max_ports) 1 else next_port_scan + 1;
        const state = &ports[port_id];
        if (state.action == .none) continue;
        if (outstanding_transfer != null and !state.retiring) continue;
        switch (state.action) {
            .reset_port => {
                const protocol = protocols.forPort(port_id) orelse return error.MissingPortProtocol;
                const register_offset = try xhci.portRegisterOffset(capabilities, port_id);
                const raw_status = reader.readReg32(register_offset);
                const status = xhci.decodePortStatus(raw_status);
                if (status.over_current) return error.InvalidPortStatus;
                if (!status.connected) {
                    reader.writeReg32(register_offset, xhci.portStatusAcknowledge(raw_status));
                    state.connected = false;
                    state.enabled = false;
                    state.speed_id = 0;
                    state.reset_deadline = null;
                    state.action = .none;
                    continue;
                }
                if (!status.powered) return error.InvalidPortStatus;
                state.connected = true;
                state.enabled = status.enabled;
                if (status.enabled) {
                    state.speed_id = status.speed;
                    state.action = .enable_slot;
                    continue;
                }
                if (protocol.kind == .usb3 and !status.cold_attach and !status.reset_active) {
                    return error.InvalidPortStatus;
                }
                if (!status.reset_active) {
                    reader.writeReg32(register_offset, xhci.portResetWrite(raw_status, protocol));
                }
                state.reset_deadline = tsc_clock.afterMilliseconds(PORT_RESET_TIMEOUT_MILLISECONDS);
                state.action = .none;
                continue;
            },
            .read_device_descriptor_prefix => {
                try submitDescriptorTransfer(
                    .device_descriptor_prefix,
                    port_id,
                    state,
                    reader,
                );
                return;
            },
            .read_device_descriptor => {
                try submitDescriptorTransfer(.device_descriptor, port_id, state, reader);
                return;
            },
            .read_configuration_descriptor_header => {
                try submitDescriptorTransfer(
                    .configuration_descriptor_header,
                    port_id,
                    state,
                    reader,
                );
                return;
            },
            .read_configuration_descriptor => {
                try submitDescriptorTransfer(
                    .configuration_descriptor,
                    port_id,
                    state,
                    reader,
                );
                return;
            },
            .set_configuration => {
                try submitSetConfigurationTransfer(port_id, state, reader);
                return;
            },
            .set_boot_protocol => {
                try submitSetBootProtocolTransfer(port_id, state, reader);
                return;
            },
            .post_interrupt_report => {
                try submitInterruptReportTransfer(port_id, state, reader);
                continue;
            },
            else => {},
        }

        var endpoint_id: u5 = 0;
        const kind: xhci.CommandKind = switch (state.action) {
            .none, .reset_port => unreachable,
            .enable_slot => .enable_slot,
            .address_device => .address_device,
            .read_device_descriptor_prefix => unreachable,
            .read_device_descriptor => unreachable,
            .read_configuration_descriptor_header => unreachable,
            .read_configuration_descriptor => unreachable,
            .set_configuration => unreachable,
            .set_boot_protocol => unreachable,
            .configure_endpoint => .configure_endpoint,
            .post_interrupt_report => unreachable,
            .evaluate_endpoint_zero => .evaluate_context,
            .disable_slot => .disable_slot,
            .retire_slot => retire: {
                const command = try nextRetirementCommand(state);
                endpoint_id = command.endpoint_id;
                break :retire command.kind;
            },
        };
        const words = switch (kind) {
            .reset_endpoint => try xhci.resetEndpointCommand(state.slot_id, endpoint_id, true, command_producer.cycle_state),
            .stop_endpoint => try xhci.stopEndpointCommand(state.slot_id, endpoint_id, false, command_producer.cycle_state),
            .enable_slot => xhci.enableSlotCommand(
                (protocols.forPort(port_id) orelse return error.MissingPortProtocol).slot_type,
                command_producer.cycle_state,
            ),
            .disable_slot => try xhci.disableSlotCommand(
                state.slot_id,
                command_producer.cycle_state,
            ),
            .address_device => address: {
                try prepareAddressDeviceInputContext(port_id, state);
                break :address try xhci.addressDeviceCommand(
                    plan.arena.input_context_address,
                    state.slot_id,
                    command_producer.cycle_state,
                );
            },
            .configure_endpoint => configure: {
                try prepareConfigureBootKeyboardInputContext(state);
                break :configure try xhci.configureEndpointCommand(
                    plan.arena.input_context_address,
                    state.slot_id,
                    command_producer.cycle_state,
                );
            },
            .evaluate_context => evaluate: {
                try prepareEvaluateEndpointZeroInputContext(state);
                break :evaluate try xhci.evaluateContextCommand(
                    plan.arena.input_context_address,
                    state.slot_id,
                    command_producer.cycle_state,
                );
            },
        };
        const command_address = try writeRingTrb(
            &command_producer,
            plan.ring_plan.command_ring_address,
            plan.ring_plan.command_ring_trbs,
            words,
        );
        publishDmaStructures();
        state.action = .none;
        outstanding_command = .{
            .kind = kind,
            .trb_address = command_address,
            .port_id = port_id,
            .slot_id = state.slot_id,
            .endpoint_id = endpoint_id,
            .deadline = tsc_clock.afterMilliseconds(COMMAND_TIMEOUT_MILLISECONDS),
        };
        try xhci.ringCommandDoorbell(capabilities, reader);
        return;
    }
}

fn writeRingTrb(
    producer: *xhci.TrbRingProducer,
    ring_address: u64,
    ring_trbs: u32,
    words: [4]u32,
) Error!u64 {
    const trb_address = try producer.trbAddress(ring_address, ring_trbs);
    const cycle_state = producer.cycle_state;
    const trb: [*]volatile u32 = @ptrFromInt(try active_dma_memory.aliasFor(
        trb_address,
        @intCast(xhci.TRB_BYTES),
    ));
    trb[0] = words[0];
    trb[1] = words[1];
    trb[2] = words[2];
    trb[3] = words[3];
    if (try producer.advance(ring_trbs)) {
        const link_address = try producer.linkAddress(ring_address, ring_trbs);
        const link: [*]volatile u32 = @ptrFromInt(try active_dma_memory.aliasFor(
            link_address,
            @intCast(xhci.TRB_BYTES),
        ));
        link[3] = xhci.ringLinkControl(cycle_state);
    }
    return trb_address;
}

fn submitInterruptReportTransfer(
    port_id: u8,
    state: *PortRuntimeState,
    reader: anytype,
) Error!void {
    const capabilities = active_capabilities orelse return error.TrbRingStateInvalid;
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    const keyboard = state.boot_keyboard orelse return error.InvalidDeviceSlot;
    if (!state.connected or !state.enabled or !state.addressed or state.slot_id == 0 or
        slot_to_port[state.slot_id] != port_id or !state.configuration_set or
        !state.boot_protocol_set or !state.endpoint_configured or
        state.interrupt_report_trb_address != 0 or
        keyboard.max_packet_size < xhci.HID_BOOT_KEYBOARD_REPORT_BYTES)
    {
        return error.InvalidDeviceSlot;
    }
    if (!keyboardReports().hasCapacity(outstanding_interrupt_reports + 1)) {
        state.action = .none;
        return;
    }

    const buffer_address = try plan.arena.interruptReportBufferAddress(state.slot_id);
    const buffer: [*]volatile u8 = @ptrFromInt(try active_dma_memory.aliasFor(
        buffer_address,
        xhci.HID_BOOT_KEYBOARD_REPORT_BYTES,
    ));
    for (0..xhci.HID_BOOT_KEYBOARD_REPORT_BYTES) |index| buffer[index] = 0;

    const ring_address = try plan.arena.interruptTransferRingAddress(state.slot_id);
    const producer = &interrupt_producers[state.slot_id];
    const words = try xhci.interruptInTransfer(
        buffer_address,
        xhci.HID_BOOT_KEYBOARD_REPORT_BYTES,
        producer.cycle_state,
    );
    const trb_address = try writeRingTrb(
        producer,
        ring_address,
        plan.arena.interrupt_transfer_ring_trbs,
        words,
    );
    publishDmaStructures();
    state.action = .none;
    state.interrupt_report_trb_address = trb_address;
    try xhci.ringDeviceDoorbell(
        capabilities,
        state.slot_id,
        keyboard.device_context_index,
        reader,
    );
    outstanding_interrupt_reports += 1;
    interrupt_report_submission_count +%= 1;
}

fn submitDescriptorTransfer(
    kind: ControlTransferKind,
    port_id: u8,
    state: *PortRuntimeState,
    reader: anytype,
) Error!void {
    const capabilities = active_capabilities orelse return error.TrbRingStateInvalid;
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    if (!state.connected or !state.enabled or !state.addressed or
        state.slot_id == 0 or state.endpoint_zero_max_packet_size == 0 or
        state.pending_endpoint_zero_max_packet_size != 0)
    {
        return error.InvalidDeviceSlot;
    }
    switch (kind) {
        .device_descriptor_prefix => if (state.descriptor_prefix_valid or
            state.device_descriptor != null or
            state.pending_endpoint_zero_max_packet_size != 0)
        {
            return error.InvalidDeviceSlot;
        },
        .device_descriptor => if (!state.descriptor_prefix_valid or
            state.device_descriptor != null or
            state.configuration_descriptor_header != null or
            state.configuration_descriptor != null)
        {
            return error.InvalidDeviceSlot;
        },
        .configuration_descriptor_header => if (state.device_descriptor == null or
            state.configuration_descriptor_header != null or
            state.configuration_descriptor != null)
        {
            return error.InvalidDeviceSlot;
        },
        .configuration_descriptor => if (state.device_descriptor == null or
            state.configuration_descriptor_header == null or
            state.configuration_descriptor != null)
        {
            return error.InvalidDeviceSlot;
        },
        .set_configuration => unreachable,
        .set_boot_protocol => unreachable,
    }
    const transfer_bytes: u17 = switch (kind) {
        .device_descriptor_prefix => xhci.USB_DEVICE_DESCRIPTOR_PREFIX_BYTES,
        .device_descriptor => xhci.USB_DEVICE_DESCRIPTOR_BYTES,
        .configuration_descriptor_header => xhci.USB_CONFIGURATION_DESCRIPTOR_BYTES,
        .configuration_descriptor => state.configuration_descriptor_header.?.total_length,
        .set_configuration => unreachable,
        .set_boot_protocol => unreachable,
    };
    if (transfer_bytes > plan.arena.enumeration_buffer_bytes or
        plan.arena.enumeration_buffer_address % xhci.XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES != 0)
    {
        return error.DmaAddressOutsidePlan;
    }
    const descriptor_type: u8 = switch (kind) {
        .device_descriptor_prefix, .device_descriptor => xhci.USB_DESCRIPTOR_DEVICE,
        .configuration_descriptor_header, .configuration_descriptor => xhci.USB_DESCRIPTOR_CONFIGURATION,
        .set_configuration => unreachable,
        .set_boot_protocol => unreachable,
    };
    const buffer: [*]volatile u8 = @ptrFromInt(try active_dma_memory.aliasFor(
        plan.arena.enumeration_buffer_address,
        @intCast(transfer_bytes),
    ));
    for (0..transfer_bytes) |index| buffer[index] = 0;

    const ring_address = try plan.arena.controlTransferRingAddress(state.slot_id);
    const producer = &control_producers[state.slot_id];
    const setup = try xhci.getDescriptorSetupStage(
        descriptor_type,
        0,
        @intCast(transfer_bytes),
        producer.cycle_state,
    );
    _ = try writeRingTrb(producer, ring_address, plan.arena.control_transfer_ring_trbs, setup);
    const data = try xhci.controlInDataStage(
        plan.arena.enumeration_buffer_address,
        transfer_bytes,
        producer.cycle_state,
    );
    _ = try writeRingTrb(producer, ring_address, plan.arena.control_transfer_ring_trbs, data);
    const status = xhci.controlOutStatusStage(producer.cycle_state);
    const status_address = try writeRingTrb(
        producer,
        ring_address,
        plan.arena.control_transfer_ring_trbs,
        status,
    );
    publishDmaStructures();
    state.action = .none;
    outstanding_transfer = .{
        .kind = kind,
        .status_trb_address = status_address,
        .port_id = port_id,
        .slot_id = state.slot_id,
        .deadline = tsc_clock.afterMilliseconds(CONTROL_TRANSFER_TIMEOUT_MILLISECONDS),
    };
    try xhci.ringDeviceDoorbell(capabilities, state.slot_id, xhci.ENDPOINT_ZERO_DCI, reader);
}

fn submitSetConfigurationTransfer(
    port_id: u8,
    state: *PortRuntimeState,
    reader: anytype,
) Error!void {
    const capabilities = active_capabilities orelse return error.TrbRingStateInvalid;
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    const configuration = state.configuration_descriptor orelse
        return error.InvalidDeviceSlot;
    const keyboard = state.boot_keyboard orelse return error.InvalidDeviceSlot;
    if (!state.connected or !state.enabled or !state.addressed or state.slot_id == 0 or
        state.endpoint_zero_max_packet_size == 0 or state.configuration_set or
        state.boot_protocol_set or state.endpoint_configured or
        keyboard.configuration_value != configuration.configuration_value)
    {
        return error.InvalidDeviceSlot;
    }

    const ring_address = try plan.arena.controlTransferRingAddress(state.slot_id);
    const producer = &control_producers[state.slot_id];
    const setup = try xhci.setConfigurationSetupStage(
        keyboard.configuration_value,
        producer.cycle_state,
    );
    _ = try writeRingTrb(producer, ring_address, plan.arena.control_transfer_ring_trbs, setup);
    const status_address = try writeRingTrb(
        producer,
        ring_address,
        plan.arena.control_transfer_ring_trbs,
        xhci.controlInStatusStage(producer.cycle_state),
    );
    publishDmaStructures();
    state.action = .none;
    outstanding_transfer = .{
        .kind = .set_configuration,
        .status_trb_address = status_address,
        .port_id = port_id,
        .slot_id = state.slot_id,
        .deadline = tsc_clock.afterMilliseconds(CONTROL_TRANSFER_TIMEOUT_MILLISECONDS),
    };
    try xhci.ringDeviceDoorbell(capabilities, state.slot_id, xhci.ENDPOINT_ZERO_DCI, reader);
}

fn submitSetBootProtocolTransfer(
    port_id: u8,
    state: *PortRuntimeState,
    reader: anytype,
) Error!void {
    const capabilities = active_capabilities orelse return error.TrbRingStateInvalid;
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    const configuration = state.configuration_descriptor orelse
        return error.InvalidDeviceSlot;
    const keyboard = state.boot_keyboard orelse return error.InvalidDeviceSlot;
    if (!state.connected or !state.enabled or !state.addressed or state.slot_id == 0 or
        state.endpoint_zero_max_packet_size == 0 or !state.configuration_set or
        state.boot_protocol_set or state.endpoint_configured or
        keyboard.configuration_value != configuration.configuration_value)
    {
        return error.InvalidDeviceSlot;
    }

    const ring_address = try plan.arena.controlTransferRingAddress(state.slot_id);
    const producer = &control_producers[state.slot_id];
    _ = try writeRingTrb(
        producer,
        ring_address,
        plan.arena.control_transfer_ring_trbs,
        xhci.setBootProtocolSetupStage(keyboard.interface_number, producer.cycle_state),
    );
    const status_address = try writeRingTrb(
        producer,
        ring_address,
        plan.arena.control_transfer_ring_trbs,
        xhci.controlInStatusStage(producer.cycle_state),
    );
    publishDmaStructures();
    state.action = .none;
    outstanding_transfer = .{
        .kind = .set_boot_protocol,
        .status_trb_address = status_address,
        .port_id = port_id,
        .slot_id = state.slot_id,
        .deadline = tsc_clock.afterMilliseconds(CONTROL_TRANSFER_TIMEOUT_MILLISECONDS),
    };
    try xhci.ringDeviceDoorbell(capabilities, state.slot_id, xhci.ENDPOINT_ZERO_DCI, reader);
}

fn prepareAddressDeviceInputContext(port_id: u8, state: *PortRuntimeState) Error!void {
    const capabilities = active_capabilities orelse return error.CommandRingStateInvalid;
    const protocols = active_protocols orelse return error.MissingSupportedProtocols;
    const plan = active_dma_plan orelse return error.CommandRingStateInvalid;
    if (!state.connected or !state.enabled or state.addressed or state.slot_id == 0) {
        return error.InvalidDeviceSlot;
    }
    const protocol = protocols.forPort(port_id) orelse return error.MissingPortProtocol;
    const max_packet_size = try xhci.endpointZeroMaxPacketSize(protocol, state.speed_id);
    const input_context: [*]u8 = @ptrFromInt(try active_dma_memory.aliasFor(
        plan.arena.input_context_address,
        @intCast(plan.arena.input_context_bytes),
    ));
    try xhci.initializeAddressDeviceInputContext(
        capabilities.context_size,
        port_id,
        state.speed_id,
        max_packet_size,
        try plan.arena.controlTransferRingAddress(state.slot_id),
        input_context[0..plan.arena.input_context_bytes],
    );
    clearPortDescriptorState(state);
    state.endpoint_zero_max_packet_size = max_packet_size;
}

fn prepareConfigureBootKeyboardInputContext(state: *const PortRuntimeState) Error!void {
    const capabilities = active_capabilities orelse return error.CommandRingStateInvalid;
    const plan = active_dma_plan orelse return error.CommandRingStateInvalid;
    const configuration = state.configuration_descriptor orelse
        return error.InvalidDeviceSlot;
    const keyboard = state.boot_keyboard orelse return error.InvalidDeviceSlot;
    if (!state.connected or !state.enabled or !state.addressed or state.slot_id == 0 or
        !state.configuration_set or !state.boot_protocol_set or state.endpoint_configured or
        keyboard.configuration_value != configuration.configuration_value)
    {
        return error.InvalidDeviceSlot;
    }
    const input_context: [*]u8 = @ptrFromInt(try active_dma_memory.aliasFor(
        plan.arena.input_context_address,
        @intCast(plan.arena.input_context_bytes),
    ));
    try xhci.initializeConfigureInterruptInEndpointInputContext(
        capabilities.context_size,
        keyboard,
        try plan.arena.interruptTransferRingAddress(state.slot_id),
        input_context[0..plan.arena.input_context_bytes],
    );
}

fn prepareEvaluateEndpointZeroInputContext(state: *const PortRuntimeState) Error!void {
    const capabilities = active_capabilities orelse return error.CommandRingStateInvalid;
    const plan = active_dma_plan orelse return error.CommandRingStateInvalid;
    if (!state.connected or !state.enabled or !state.addressed or
        state.descriptor_prefix_valid or state.slot_id == 0 or
        state.pending_endpoint_zero_max_packet_size == 0)
    {
        return error.InvalidDeviceSlot;
    }
    const input_context: [*]u8 = @ptrFromInt(try active_dma_memory.aliasFor(
        plan.arena.input_context_address,
        @intCast(plan.arena.input_context_bytes),
    ));
    try xhci.initializeEvaluateEndpointZeroInputContext(
        capabilities.context_size,
        state.pending_endpoint_zero_max_packet_size,
        input_context[0..plan.arena.input_context_bytes],
    );
}

fn resetSlotTransferRings(slot_id: u8) Error!void {
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    try xhci.resetTransferRing(
        plan,
        active_dma_memory.bytes(),
        try plan.arena.controlTransferRingAddress(slot_id),
        plan.arena.control_transfer_ring_trbs,
    );
    try xhci.resetTransferRing(
        plan,
        active_dma_memory.bytes(),
        try plan.arena.interruptTransferRingAddress(slot_id),
        plan.arena.interrupt_transfer_ring_trbs,
    );
    control_producers[slot_id] = .{};
    interrupt_producers[slot_id] = .{};
    publishDmaStructures();
}

fn writeDcbaaSlot(slot_id: u8, address: u64) Error!void {
    const plan = active_dma_plan orelse return error.CommandRingStateInvalid;
    if (slot_id == 0 or slot_id > plan.arena.enabled_device_slots) {
        return error.InvalidDeviceSlot;
    }
    const entry_address = std.math.add(
        u64,
        plan.arena.dcbaa_address,
        @as(u64, slot_id) * xhci.DCBAA_ENTRY_BYTES,
    ) catch return error.DmaAddressOutsidePlan;
    @as(*volatile u64, @ptrFromInt(try active_dma_memory.aliasFor(
        entry_address,
        @sizeOf(u64),
    ))).* = address;
    publishDmaStructures();
}

fn clearDeviceContext(slot_id: u8) Error!void {
    const plan = active_dma_plan orelse return error.CommandRingStateInvalid;
    const address = try plan.arena.deviceContextAddress(slot_id);
    const bytes: usize = @intCast(plan.arena.device_context_stride);
    const context: [*]u8 = @ptrFromInt(try active_dma_memory.aliasFor(address, bytes));
    @memset(context[0..bytes], 0);
    publishDmaStructures();
}

fn currentEventReady() bool {
    const plan = active_dma_plan orelse return false;
    const control_address = plan.ring_plan.event_ring_address +
        @as(u64, event_consumer.dequeue_index) * xhci.TRB_BYTES +
        3 * @sizeOf(u32);
    const control_alias = active_dma_memory.aliasFor(control_address, @sizeOf(u32)) catch
        return false;
    const control = @as(*volatile u32, @ptrFromInt(control_alias)).*;
    return event_consumer.ready(control);
}

fn readCurrentEvent() ?[4]u32 {
    const plan = active_dma_plan orelse return null;
    const trb_address = plan.ring_plan.event_ring_address +
        @as(u64, event_consumer.dequeue_index) * xhci.TRB_BYTES;
    const trb_alias = active_dma_memory.aliasFor(
        trb_address,
        @intCast(xhci.TRB_BYTES),
    ) catch return null;
    const trb: [*]volatile u32 = @ptrFromInt(trb_alias);
    const control = trb[3];
    if (!event_consumer.ready(control)) return null;
    acquireEvent();
    return .{ trb[0], trb[1], trb[2], control };
}

fn acquireEvent() void {
    asm volatile ("lfence" ::: .{ .memory = true });
}

fn pollDmaFault() bool {
    if (!intel_vtd.faultMonitoringEnabled()) {
        containFailure("ZIGOS:XHCI:HW:FAULT_MONITOR_UNAVAILABLE\n");
        return true;
    }
    if ((intel_vtd.pollFaultForDevice(active_device) catch {
        containFailure("ZIGOS:XHCI:HW:FAULT_MONITOR_FAIL_CLOSED\n");
        return true;
    }) != null) {
        containFailure("ZIGOS:XHCI:HW:DMA_FAULT_CONTAINED\n");
        return true;
    }
    return false;
}

fn containFailure(marker: []const u8) void {
    publishControllerActive(false);
    @atomicStore(u32, &pending_interrupts, 0, .monotonic);
    outstanding_command = null;
    outstanding_transfer = null;
    command_producer = .{};
    control_producers = @as([xhci.MAX_DEVICE_SLOTS + 1]xhci.TrbRingProducer, @splat(.{}));
    resetControllerRuntimeState();
    if (active_capabilities) |capabilities| {
        if (active_bar_address != 0) {
            var reader = ExtendedCapabilityReader{ .bar_address = active_bar_address };
            xhci.quiesceOwnedController(capabilities, &reader);
        }
    }
    pci.disableMsi(active_device) catch {};
    pci.disableBusMastering(active_device);
    console.print(marker);
}

fn buildDmaWindows(
    plan: xhci.ControllerDmaPlan,
    windows: *[xhci.MAX_CONTROLLER_DMA_REGIONS]intel_vtd.DmaWindow,
) Error!usize {
    var region_storage: [xhci.MAX_CONTROLLER_DMA_REGIONS]xhci.DmaAccessRegion = undefined;
    const regions = try xhci.controllerDmaAccessRegions(plan, &region_storage);
    for (regions, 0..) |region, index| {
        const region_end = std.math.add(u64, region.address, region.bytes) catch
            return error.DmaIsolationPlanInvalid;
        if (region_end > std.math.maxInt(u32)) return error.DmaIsolationPlanInvalid;
        windows[index] = .{
            .base = std.math.cast(u32, region.address) orelse
                return error.DmaIsolationPlanInvalid,
            .length = std.math.cast(u32, region.bytes) orelse
                return error.DmaIsolationPlanInvalid,
            .device_readable = region.device_readable,
            .device_writable = region.device_writable,
        };
    }
    return regions.len;
}

fn publishDmaStructures() void {
    asm volatile ("mfence" ::: .{ .memory = true });
}

const InvariantClock = struct {
    pub fn afterMilliseconds(_: @This(), milliseconds: u64) tsc_clock.Deadline {
        return tsc_clock.afterMilliseconds(milliseconds);
    }
};

fn validateBar(device_info: pci.PCIDevice) Error!pci.MemoryBar {
    if (!pci.isXhciController(device_info)) return error.NotXhciController;
    const bar = pci.memoryBar0(device_info) orelse return error.BarUnmappable;
    if (bar.address == 0) return error.BarUnmappable;
    if (bar.address % PAGE_BYTES != 0) return error.BarMisaligned;
    return bar;
}

fn validateExtendedCapabilityRange(bar_address: usize, first_offset: u32) Error!void {
    if (first_offset == 0) return;
    if (bar_address > std.math.maxInt(usize) - @as(usize, xhci.MAX_EXTENDED_CAPABILITY_OFFSET)) {
        return error.BarRangeOverflow;
    }
}

fn validateControllerRegisterRanges(
    bar_address: usize,
    capabilities: xhci.CapabilityRegisters,
) Error!void {
    const operational_bytes = @as(u64, 0x400) +
        @as(u64, capabilities.max_ports) * 0x10;
    const doorbell_bytes = (@as(u64, capabilities.max_device_slots) + 1) * @sizeOf(u32);
    try validateBarRange(bar_address, capabilities.capability_length, operational_bytes);
    try validateBarRange(bar_address, capabilities.runtime_register_offset, 0x40);
    try validateBarRange(bar_address, capabilities.doorbell_offset, doorbell_bytes);
}

fn validateBarRange(bar_address: usize, offset: u64, byte_count: u64) Error!void {
    const end = std.math.add(u64, offset, byte_count) catch return error.BarRangeOverflow;
    const end_offset = std.math.cast(usize, end) orelse return error.BarRangeOverflow;
    if (bar_address > std.math.maxInt(usize) - end_offset) return error.BarRangeOverflow;
}

const ExtendedCapabilityReader = struct {
    bar_address: usize,
    mapped_page_offset: ?usize = null,
    mapped_writable: bool = false,

    pub fn readDword(self: *@This(), offset: u32) u32 {
        const byte_offset: usize = @intCast(offset);
        const page_offset = byte_offset & ~(PAGE_BYTES - 1);
        self.mapPage(page_offset, false);
        const page_byte_offset = byte_offset & (PAGE_BYTES - 1);
        return @as(*volatile u32, @ptrFromInt(mmio_windows.xhci.base + page_byte_offset)).*;
    }

    pub fn writeOsOwnedByte(self: *@This(), legacy_offset: u32, value: u8) void {
        const byte_offset = @as(usize, legacy_offset) + OS_OWNED_BYTE_OFFSET;
        const page_offset = byte_offset & ~(PAGE_BYTES - 1);
        self.mapPage(page_offset, true);
        const page_byte_offset = byte_offset & (PAGE_BYTES - 1);
        @as(*volatile u8, @ptrFromInt(mmio_windows.xhci.base + page_byte_offset)).* = value;
        self.mapPage(page_offset, false);
    }

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        return self.readDword(offset);
    }

    pub fn readReg64(self: *@This(), offset: u32) u64 {
        const low = self.readDword(offset);
        const high = self.readDword(offset + @sizeOf(u32));
        return @as(u64, low) | (@as(u64, high) << 32);
    }

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        const byte_offset: usize = @intCast(offset);
        const page_offset = byte_offset & ~(PAGE_BYTES - 1);
        self.mapPage(page_offset, true);
        const page_byte_offset = byte_offset & (PAGE_BYTES - 1);
        @as(*volatile u32, @ptrFromInt(mmio_windows.xhci.base + page_byte_offset)).* = value;
        self.mapPage(page_offset, false);
    }

    pub fn writeReg64(self: *@This(), offset: u32, value: u64) void {
        self.writeReg32(offset, @truncate(value));
        self.writeReg32(offset + @sizeOf(u32), @truncate(value >> 32));
    }

    fn mapPage(self: *@This(), page_offset: usize, writable: bool) void {
        if (self.mapped_page_offset != null and
            self.mapped_page_offset.? == page_offset and
            self.mapped_writable == writable)
        {
            return;
        }
        paging.mapKernelBorrowedPage(
            mmio_windows.xhci.base,
            self.bar_address + page_offset,
            paging.PAGE_PRESENT |
                paging.PAGE_CACHE_DISABLE |
                (if (writable) paging.PAGE_WRITABLE else 0),
        );
        self.mapped_page_offset = page_offset;
        self.mapped_writable = writable;
    }
};

fn readCapabilitySnapshot(base: usize) [xhci.CAPABILITY_REGISTERS_BYTES]u8 {
    var snapshot = @as([xhci.CAPABILITY_REGISTERS_BYTES]u8, @splat(0));
    var offset: usize = 0;
    while (offset < snapshot.len) : (offset += @sizeOf(u32)) {
        const value = @as(*volatile u32, @ptrFromInt(base + offset)).*;
        endian.writeU32Le(snapshot[offset..][0..@sizeOf(u32)], value);
    }
    return snapshot;
}

fn validTestSnapshot() [xhci.CAPABILITY_REGISTERS_BYTES]u8 {
    var snapshot = @as([xhci.CAPABILITY_REGISTERS_BYTES]u8, @splat(0));
    snapshot[0] = 0x40;
    endian.writeU16Le(snapshot[2..4], 0x0110);
    endian.writeU32Le(snapshot[4..8], 32 | (@as(u32, 8) << 8) | (@as(u32, 12) << 24));
    endian.writeU32Le(snapshot[0x08..0x0C], (@as(u32, 1) << 21) | (@as(u32, 1) << 27));
    endian.writeU32Le(snapshot[0x10..0x14], 1 | (@as(u32, 1) << 2) | (@as(u32, 0x2000) << 16));
    endian.writeU32Le(snapshot[0x14..0x18], 0x2000);
    endian.writeU32Le(snapshot[0x18..0x1C], 0x1000);
    return snapshot;
}

fn testDevice(bar0: u32, bar1: u32) pci.PCIDevice {
    return .{
        .bus = 0,
        .device = 20,
        .function = 0,
        .vendor_id = pci.PCI_VENDOR_INTEL,
        .device_id = 0xA0ED,
        .class_code = pci.PCI_CLASS_SERIAL_BUS_CONTROLLER,
        .subclass = pci.PCI_SUBCLASS_USB,
        .prog_if = pci.PCI_PROG_IF_XHCI,
        .bar0 = bar0,
        .bar1 = bar1,
    };
}

test "xHCI hardware probe validates the controller and BAR before MMIO mapping" {
    const device = testDevice(0xFEB0_0004, 0);
    const bar = try validateBar(device);
    try std.testing.expectEqual(@as(usize, 0xFEB0_0000), bar.address);
    try std.testing.expectEqual(pci.MemoryBarWidth.bits64, bar.width);

    var non_xhci = device;
    non_xhci.prog_if = 0x20;
    try std.testing.expectError(error.NotXhciController, validateBar(non_xhci));
    try std.testing.expectError(error.BarUnmappable, validateBar(testDevice(1, 0)));
    try std.testing.expectError(error.BarMisaligned, validateBar(testDevice(0xFEB0_0104, 0)));
}

test "xHCI hardware capability snapshot uses the shared modern parser" {
    const snapshot = validTestSnapshot();
    const capabilities = try xhci.parseCapabilityRegisters(&snapshot);
    try std.testing.expectEqual(@as(u16, 0x0110), capabilities.interface_version);
    try std.testing.expectEqual(@as(u8, 32), capabilities.max_device_slots);
    try std.testing.expectEqual(@as(u8, 12), capabilities.max_ports);
    try std.testing.expect(capabilities.supports_64_bit_addressing);
    try std.testing.expectEqual(xhci.ContextSize.bytes_64, capabilities.context_size);
    try std.testing.expectEqual(@as(u16, 33), capabilities.max_scratchpad_buffers);
    try std.testing.expect(!capabilities.scratchpad_restore);
    try std.testing.expectEqual(@as(u32, 0x8000), capabilities.extended_capability_offset);
}

test "xHCI controller runtime state allocation follows reported hardware capacity" {
    try std.testing.expect(INTERRUPT_STATE_USES_PROTOCOL_ORDERING);
    try std.testing.expect(CONTROLLER_RUNTIME_STATE_USES_GENERAL_MEMORY);
    try std.testing.expectEqual(@as(usize, 104), @sizeOf(PortRuntimeState));
    try std.testing.expectEqual(@as(usize, 1_352), keyboardReportPublisherOffsetFor(12));
    try std.testing.expectEqual(@as(usize, 2_936), supportedProtocolsOffsetFor(12));
    try std.testing.expectEqual(@as(u32, 1), controllerRuntimeStateFrameCountFor(12));
    try std.testing.expectEqual(
        @as(u32, CONTROLLER_RUNTIME_STATE_MAX_FRAME_COUNT),
        controllerRuntimeStateFrameCountFor(std.math.maxInt(u8)),
    );
}

test "xHCI hardware probe bounds extended capability BAR arithmetic" {
    try validateExtendedCapabilityRange(0xFEB0_0000, 0x8000);
    try validateExtendedCapabilityRange(std.math.maxInt(usize), 0);
    try std.testing.expectError(
        error.BarRangeOverflow,
        validateExtendedCapabilityRange(std.math.maxInt(usize), 0x8000),
    );

    const capabilities = xhci.defaultCapabilityRegisters();
    try validateControllerRegisterRanges(0xFEB0_0000, capabilities);
    try std.testing.expectError(
        error.BarRangeOverflow,
        validateControllerRegisterRanges(std.math.maxInt(usize), capabilities),
    );
    try std.testing.expectError(
        error.BarRangeOverflow,
        validateBarRange(0, std.math.maxInt(u64), 2),
    );
}

test "xHCI hardware DMA windows retain page-granular access directions" {
    var capabilities = xhci.defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_scratchpad_buffers = 2;
    const plan = try xhci.planControllerDma(capabilities, 1, 0x1000);
    var windows: [xhci.MAX_CONTROLLER_DMA_REGIONS]intel_vtd.DmaWindow = undefined;
    const count = try buildDmaWindows(plan, &windows);
    try std.testing.expectEqual(@as(usize, 8), count);
    try std.testing.expectEqual(@as(u32, 0x1000), windows[0].base);
    try std.testing.expect(windows[0].device_readable and !windows[0].device_writable);
    try std.testing.expect(windows[1].device_readable and windows[1].device_writable);
    try std.testing.expect(windows[2].device_readable and !windows[2].device_writable);
    try std.testing.expect(windows[4].device_readable and windows[4].device_writable);
    try std.testing.expect(windows[6].device_readable and !windows[6].device_writable);
    try std.testing.expect(!windows[7].device_readable and windows[7].device_writable);

    const outside_managed_width = try xhci.planControllerDma(
        capabilities,
        1,
        @as(u64, std.math.maxInt(u32)) & ~(xhci.XHCI_PAGE_BYTES - 1),
    );
    try std.testing.expectError(
        error.DmaIsolationPlanInvalid,
        buildDmaWindows(outside_managed_width, &windows),
    );
}

test "keyboard repeat continuity changes across device teardown and controller reset" {
    const saved_epoch = keyboard_continuity_epoch;
    const saved_active = controllerActive();
    defer {
        keyboard_continuity_epoch = saved_epoch;
        @atomicStore(bool, &active, saved_active, .release);
    }
    keyboard_continuity_epoch = 10;
    publishControllerActive(true);
    try std.testing.expectEqual(@as(?u64, 10), keyboardContinuityEpoch());
    var port = PortRuntimeState{ .endpoint_configured = true };
    clearPortDescriptorState(&port);
    try std.testing.expectEqual(@as(?u64, 11), keyboardContinuityEpoch());
    clearPortDescriptorState(&port);
    try std.testing.expectEqual(@as(?u64, 11), keyboardContinuityEpoch());
    publishControllerActive(false);
    try std.testing.expect(keyboardContinuityEpoch() == null);
    publishControllerActive(true);
    try std.testing.expectEqual(@as(?u64, 12), keyboardContinuityEpoch());
    keyboard_continuity_epoch = std.math.maxInt(u64);
    publishControllerActive(false);
    publishControllerActive(true);
    try std.testing.expect(keyboardContinuityEpoch() == null);
}

// This fixture invokes the hardware lifecycle handlers with host-owned register
// and DMA storage. It never changes the production MMIO mapping path.
const HotplugTestFixture = struct {
    states: [3]PortRuntimeState = @splat(.{}),
    reports: xhci.BootKeyboardReportPublisher = .{},
    protocols: xhci.SupportedProtocols = .{},
    status: u32 = 0,
    dma: []align(64) u8 = &.{},
    command_doorbells: usize = 0,
    port_writes: usize = 0,
    transfer_doorbells: usize = 0,
    saved_plan: ?xhci.ControllerDmaPlan,
    saved_memory: ControllerDmaMemory,
    saved_command_producer: xhci.TrbRingProducer,
    saved_control_producers: [xhci.MAX_DEVICE_SLOTS + 1]xhci.TrbRingProducer,
    saved_interrupt_producers: [xhci.MAX_DEVICE_SLOTS + 1]xhci.TrbRingProducer,
    saved_consumer: xhci.EventRingConsumer,
    saved_scan: u16,
    saved_port_events: u64,
    saved_command_events: u64,
    saved_transfer_events: u64,
    saved_configure_count: u64,
    saved_keyboard_count: u64,
    saved_submission_count: u64,
    saved_ports: []PortRuntimeState,
    saved_reports: ?*xhci.BootKeyboardReportPublisher,
    saved_protocols: ?*const xhci.SupportedProtocols,
    saved_capabilities: ?xhci.CapabilityRegisters,
    saved_slots: u8,
    saved_slot_to_port: [xhci.MAX_DEVICE_SLOTS + 1]u8,
    saved_interrupt_reports: usize,
    saved_command: ?OutstandingCommand,
    saved_transfer: ?OutstandingTransfer,
    saved_epoch: u64,
    saved_active: bool,
    saved_clock_frequency: u64 = 0,

    fn init() @This() {
        return .{
            .saved_plan = active_dma_plan,
            .saved_memory = active_dma_memory,
            .saved_command_producer = command_producer,
            .saved_control_producers = control_producers,
            .saved_interrupt_producers = interrupt_producers,
            .saved_consumer = event_consumer,
            .saved_scan = next_port_scan,
            .saved_port_events = port_status_change_count,
            .saved_command_events = command_completion_count,
            .saved_transfer_events = transfer_completion_count,
            .saved_configure_count = configure_endpoint_count,
            .saved_keyboard_count = keyboard_report_count,
            .saved_submission_count = interrupt_report_submission_count,
            .saved_ports = ports,
            .saved_reports = active_keyboard_reports,
            .saved_protocols = active_protocols,
            .saved_capabilities = active_capabilities,
            .saved_slots = active_enabled_slots,
            .saved_slot_to_port = slot_to_port,
            .saved_interrupt_reports = outstanding_interrupt_reports,
            .saved_command = outstanding_command,
            .saved_transfer = outstanding_transfer,
            .saved_epoch = keyboard_continuity_epoch,
            .saved_active = controllerActive(),
        };
    }

    fn activate(self: *@This()) !void {
        var capabilities = xhci.defaultCapabilityRegisters();
        capabilities.max_ports = 2;
        capabilities.max_device_slots = 2;
        capabilities.max_scratchpad_buffers = 0;
        const plan = try xhci.planControllerDma(capabilities, 2, 0x1000);
        self.dma = try std.testing.allocator.alignedAlloc(u8, .@"64", @intCast(plan.total_bytes));
        @memset(self.dma, 0);
        self.saved_clock_frequency = tsc_clock.swapTestFrequency(1_000_000_000);
        active_dma_plan = plan;
        active_dma_memory = .{ .physical_base = 0x1000, .alias_base = @intFromPtr(self.dma.ptr), .byte_len = self.dma.len };
        command_producer = .{};
        control_producers = @splat(.{});
        interrupt_producers = @splat(.{});
        event_consumer = .{};
        next_port_scan = 1;
        active_capabilities = capabilities;
        @atomicStore(bool, &active, true, .release);
        active_enabled_slots = 2;
        self.protocols.range_count = 1;
        self.protocols.first_ports[0] = 1;
        self.protocols.port_counts[0] = 2;
        self.protocols.speed_classes[0] = (@as(u32, 1) << 3) | (@as(u32, 1) << 19);
        active_protocols = &self.protocols;
        ports = &self.states;
        active_keyboard_reports = &self.reports;
        slot_to_port = @splat(0);
        slot_to_port[1] = 1;
        outstanding_interrupt_reports = 1;
        outstanding_command = null;
        outstanding_transfer = null;
        self.states[1] = .{
            .connected = true,
            .enabled = true,
            .addressed = true,
            .descriptor_prefix_valid = true,
            .device_descriptor = .{
                .usb_version_bcd = 0x0200,
                .device_class = 0,
                .device_subclass = 0,
                .device_protocol = 0,
                .endpoint_zero_max_packet_size = 64,
                .vendor_id = 1,
                .product_id = 2,
                .device_version_bcd = 0x0100,
                .manufacturer_string_index = 0,
                .product_string_index = 0,
                .serial_number_string_index = 0,
                .configuration_count = 1,
            },
            .boot_keyboard = .{
                .configuration_value = 1,
                .interface_number = 0,
                .endpoint_id = 0x81,
                .device_context_index = 3,
                .max_packet_size = 8,
                .max_burst_size = 0,
                .interval = 4,
                .max_esit_payload = 8,
            },
            .configuration_set = true,
            .boot_protocol_set = true,
            .endpoint_configured = true,
            .speed_id = 3,
            .slot_id = 1,
            .endpoint_zero_max_packet_size = 64,
            .interrupt_report_trb_address = try plan.arena.interruptTransferRingAddress(1),
        };
        interrupt_producers[1].enqueue_index = 1;
        try self.endpointState(xhci.ENDPOINT_ZERO_DCI, .running);
        try self.endpointState(3, .running);
    }

    fn endpointState(_: *@This(), endpoint_id: u5, value: xhci.EndpointState) !void {
        const address = try active_dma_plan.?.arena.deviceContextAddress(1);
        const offset = @as(u64, endpoint_id) * active_capabilities.?.context_size.byteCount();
        const alias = try active_dma_memory.aliasFor(address + offset, @sizeOf(u32));
        @as(*u32, @ptrFromInt(alias)).* = @backingInt(value);
    }

    fn restore(self: *@This()) void {
        active_dma_plan = self.saved_plan;
        active_dma_memory = self.saved_memory;
        command_producer = self.saved_command_producer;
        control_producers = self.saved_control_producers;
        interrupt_producers = self.saved_interrupt_producers;
        event_consumer = self.saved_consumer;
        next_port_scan = self.saved_scan;
        port_status_change_count = self.saved_port_events;
        command_completion_count = self.saved_command_events;
        transfer_completion_count = self.saved_transfer_events;
        configure_endpoint_count = self.saved_configure_count;
        keyboard_report_count = self.saved_keyboard_count;
        interrupt_report_submission_count = self.saved_submission_count;
        std.testing.allocator.free(self.dma);
        ports = self.saved_ports;
        active_keyboard_reports = self.saved_reports;
        active_protocols = self.saved_protocols;
        active_capabilities = self.saved_capabilities;
        active_enabled_slots = self.saved_slots;
        slot_to_port = self.saved_slot_to_port;
        outstanding_interrupt_reports = self.saved_interrupt_reports;
        outstanding_command = self.saved_command;
        outstanding_transfer = self.saved_transfer;
        keyboard_continuity_epoch = self.saved_epoch;
        @atomicStore(bool, &active, self.saved_active, .release);
        _ = tsc_clock.swapTestFrequency(self.saved_clock_frequency);
    }

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        std.debug.assert(offset == xhci.portRegisterOffset(active_capabilities.?, 1) catch unreachable);
        return self.status;
    }

    pub fn writeReg32(self: *@This(), offset: u32, _: u32) void {
        if (offset == active_capabilities.?.doorbell_offset) {
            self.command_doorbells += 1;
        } else if (offset == active_capabilities.?.doorbell_offset + @sizeOf(u32)) {
            self.transfer_doorbells += 1;
        } else {
            std.debug.assert(offset == xhci.portRegisterOffset(active_capabilities.?, 1) catch unreachable);
            self.port_writes += 1;
        }
    }

    fn queuedEvents(self: *@This(), events: []const [4]u32) Error!void {
        const plan = active_dma_plan.?;
        if (event_consumer.dequeue_index + events.len > plan.ring_plan.event_ring_trbs) {
            return error.EventRingStateInvalid;
        }
        for (events, 0..) |words, index| {
            const address = plan.ring_plan.event_ring_address +
                (@as(u64, event_consumer.dequeue_index) + index) * xhci.TRB_BYTES;
            const trb: *[4]u32 = @ptrFromInt(try active_dma_memory.aliasFor(address, xhci.TRB_BYTES));
            trb.* = words;
        }
        for (events) |_| {
            const words = readCurrentEvent() orelse return error.EventRingStateInvalid;
            const event = (try event_consumer.consume(words, plan.ring_plan.event_ring_trbs)) orelse
                return error.EventRingStateInvalid;
            try handleEvent(event, self);
        }
    }

    fn commandEvent(command: OutstandingCommand, code: u8) [4]u32 {
        return .{ @truncate(command.trb_address), @truncate(command.trb_address >> 32), @as(u32, code) << 24, (33 << 10) | (@as(u32, command.slot_id) << 24) | 1 };
    }

    fn transferEvent(address: u64, endpoint_id: u5, code: u8) [4]u32 {
        return .{ @truncate(address), @truncate(address >> 32), @as(u32, code) << 24, (32 << 10) | (@as(u32, endpoint_id) << 16) | (1 << 24) | 1 };
    }

    fn finishStop(self: *@This()) !void {
        const command = outstanding_command.?;
        try std.testing.expectEqual(xhci.CommandKind.stop_endpoint, command.kind);
        const plan = active_dma_plan.?;
        const control = command.endpoint_id == xhci.ENDPOINT_ZERO_DCI;
        const ring = if (control) try plan.arena.controlTransferRingAddress(1) else try plan.arena.interruptTransferRingAddress(1);
        const trbs = if (control) plan.arena.control_transfer_ring_trbs else plan.arena.interrupt_transfer_ring_trbs;
        try self.endpointState(command.endpoint_id, .stopped);
        // An idle-ring forced stop may identify the Link rather than a TD.
        try self.queuedEvents(&.{ transferEvent(ring + (trbs - 1) * xhci.TRB_BYTES, command.endpoint_id, 27), commandEvent(command, 1) });
    }

    fn portEvent(self: *@This(), connected: bool) Error!void {
        self.status = (1 << 17) | (1 << 9) |
            (if (connected) @as(u32, 1 | (1 << 1) | (3 << 10)) else 0);
        try handlePortStatusChange(xhci.decodeEvent(.{
            1 << 24, 0, 1 << 24, (34 << 10) | 1,
        }), self);
    }
};

test "xHCI hotplug accepts queued late keyboard completion without publishing" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    _ = try fixture.reports.publish(1, 1, fixture.states[1].boot_keyboard.?, fixture.states[1].device_descriptor.?, &.{ 0, 0, 4, 0, 0, 0, 0, 0 });
    const report_trb = fixture.states[1].interrupt_report_trb_address;
    try fixture.portEvent(false);
    try std.testing.expectEqual(@as(usize, 0), fixture.reports.pendingCount());
    try handleInterruptTransferCompletion(xhci.decodeEvent(.{
        @truncate(report_trb), @truncate(report_trb >> 32), 1 << 24, (32 << 10) | (3 << 16) | (1 << 24) | 1,
    }), &fixture);
    try std.testing.expectEqual(@as(usize, 0), fixture.reports.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), outstanding_interrupt_reports);
    try std.testing.expectEqual(@as(u8, 1), fixture.states[1].slot_id);
}

test "xHCI pending work keeps idle report rings quiet and observes queued DMA events" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    const saved_pending = @atomicRmw(u32, &pending_interrupts, .Xchg, 0, .monotonic);
    defer @atomicStore(u32, &pending_interrupts, saved_pending, .monotonic);
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
    try std.testing.expect(!eventWorkPending());
    try std.testing.expect(!lifecyclePending());
    const address = active_dma_plan.?.ring_plan.event_ring_address;
    const words: *[4]u32 = @ptrFromInt(try active_dma_memory.aliasFor(address, xhci.TRB_BYTES));
    words.* = HotplugTestFixture.transferEvent(fixture.states[1].interrupt_report_trb_address, 3, 1);
    try std.testing.expect(eventWorkPending());
    try std.testing.expect(!lifecyclePending());
    words.* = @splat(0);
    try std.testing.expect(!eventWorkPending());
    @atomicStore(u32, &pending_interrupts, 1, .monotonic);
    try std.testing.expect(eventWorkPending());
    @atomicStore(u32, &pending_interrupts, 0, .monotonic);
    try std.testing.expect(!eventWorkPending());
}

test "xHCI pending work retains control and retirement watchdogs until owned completions drain" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    try std.testing.expect(!lifecyclePending());
    try submitDescriptorTransfer(.configuration_descriptor_header, 1, &fixture.states[1], &fixture);
    try std.testing.expect(outstanding_transfer != null);
    try std.testing.expect(lifecyclePending());
    try fixture.portEvent(false);
    try std.testing.expect(fixture.states[1].retiring);
    try std.testing.expect(fixture.states[1].reset_deadline != null);
    try std.testing.expect(lifecyclePending());
    try submitNextPortAction(&fixture);
    try std.testing.expect(outstanding_command != null);
    try std.testing.expectEqual(PortAction.none, fixture.states[1].action);
    try std.testing.expect(lifecyclePending());
    try fixture.finishStop();
    try std.testing.expect(outstanding_transfer == null and outstanding_command == null);
    // Isolate the anchored retirement deadline from the next queued command.
    const action = fixture.states[1].action;
    fixture.states[1].action = .none;
    try std.testing.expect(lifecyclePending());
    fixture.states[1].action = action;
    try submitNextPortAction(&fixture);
    try fixture.finishStop();
    try std.testing.expect(lifecyclePending());
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.CommandKind.disable_slot, outstanding_command.?.kind);
    try std.testing.expect(lifecyclePending());
    try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(outstanding_command.?, 1)});
    try std.testing.expect(!fixture.states[1].retiring);
    try std.testing.expect(!lifecyclePending());
}

test "xHCI pending work retains reset deadlines and queued attach actions without CQ events" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    fixture.states[1] = .{};
    outstanding_interrupt_reports = 0;
    slot_to_port[1] = 0;
    // A real reset-in-progress notification owns a watchdog even when the
    // event ring is empty and no command or control TD has been submitted.
    fixture.status = (1 << 17) | (1 << 9) | (1 << 4) | (3 << 10) | 1;
    const notification = xhci.decodeEvent(.{ 1 << 24, 0, 1 << 24, (34 << 10) | 1 });
    try handlePortStatusChange(notification, &fixture);
    try std.testing.expect(fixture.states[1].reset_deadline != null);
    try std.testing.expectEqual(PortAction.none, fixture.states[1].action);
    try std.testing.expect(lifecyclePending());
    // Successful reset completion clears the deadline and queues Enable Slot.
    try fixture.portEvent(true);
    try std.testing.expect(fixture.states[1].reset_deadline == null);
    try std.testing.expectEqual(PortAction.enable_slot, fixture.states[1].action);
    try std.testing.expect(outstanding_command == null and outstanding_transfer == null);
    try std.testing.expect(lifecyclePending());
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.CommandKind.enable_slot, outstanding_command.?.kind);
    try std.testing.expectEqual(PortAction.none, fixture.states[1].action);
    try std.testing.expect(lifecyclePending());
}

test "xHCI hotplug reconnect cannot address the slot pending retirement" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    try fixture.portEvent(false);
    try fixture.portEvent(true);
    try std.testing.expect(fixture.states[1].action != .address_device);
    try std.testing.expectEqual(@as(u8, 1), fixture.states[1].slot_id);
}

test "xHCI hotplug stops both owned endpoints before disable and reconnect" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    const report_trb = fixture.states[1].interrupt_report_trb_address;
    try fixture.portEvent(false);
    const deadline = fixture.states[1].reset_deadline.?;
    try fixture.portEvent(true);
    try std.testing.expectEqualDeep(deadline, fixture.states[1].reset_deadline.?);
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.ENDPOINT_ZERO_DCI, outstanding_command.?.endpoint_id);
    try fixture.finishStop();
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(@as(u5, 3), outstanding_command.?.endpoint_id);
    // The successful report can precede the additional forced idle-ring event.
    try fixture.queuedEvents(&.{HotplugTestFixture.transferEvent(report_trb, 3, 1)});
    try std.testing.expectEqual(@as(usize, 0), outstanding_interrupt_reports);
    try fixture.finishStop();
    try std.testing.expectEqual(@as(usize, 0), outstanding_interrupt_reports);
    try std.testing.expectEqual(@as(usize, 0), fixture.reports.pendingCount());
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.CommandKind.disable_slot, outstanding_command.?.kind);
    try std.testing.expectEqual(@as(u8, 1), slot_to_port[1]);
    try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(outstanding_command.?, 1)});
    try std.testing.expectEqual(@as(u8, 0), slot_to_port[1]);
    try std.testing.expectEqual(@as(u8, 0), fixture.states[1].slot_id);
    try std.testing.expect(!fixture.states[1].retiring);
    try std.testing.expectEqual(PortAction.enable_slot, fixture.states[1].action);
    try std.testing.expectEqual(@as(usize, 3), fixture.command_doorbells);
    try std.testing.expectError(error.InvalidDeviceSlot, handleInterruptTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(report_trb, 3, 1)), &fixture));
}

test "xHCI hotplug stops a pending control TD without extending the retirement deadline" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    const ring = try active_dma_plan.?.arena.controlTransferRingAddress(1);
    outstanding_transfer = .{ .kind = .device_descriptor, .status_trb_address = ring + 2 * xhci.TRB_BYTES, .port_id = 1, .slot_id = 1, .deadline = .{ .value = .{ .start_ticks = 0, .interval_ticks = 1 } } };
    try std.testing.expect(controlTransferTimedOut());
    try fixture.portEvent(false);
    const retirement_deadline = fixture.states[1].reset_deadline.?;
    try std.testing.expect(!controlTransferTimedOut());
    try fixture.portEvent(false);
    try fixture.portEvent(true);
    try std.testing.expectEqualDeep(retirement_deadline, fixture.states[1].reset_deadline.?);
    try submitNextPortAction(&fixture);
    const command = outstanding_command.?;
    try std.testing.expectEqual(xhci.CommandKind.stop_endpoint, command.kind);
    try std.testing.expectEqual(xhci.ENDPOINT_ZERO_DCI, command.endpoint_id);
    try fixture.endpointState(1, .stopped);
    // Stop can interrupt Setup/Data, rather than the final Status TRB.
    try fixture.queuedEvents(&.{ HotplugTestFixture.transferEvent(ring, 1, 26), HotplugTestFixture.commandEvent(command, 1) });
    try std.testing.expect(outstanding_transfer == null);
    try std.testing.expect(outstanding_command == null);
    try std.testing.expectEqual(PortAction.retire_slot, fixture.states[1].action);
}

test "xHCI hotplug empty control stop preserves another port transfer" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    outstanding_transfer = .{ .kind = .device_descriptor, .status_trb_address = try active_dma_plan.?.arena.controlTransferRingAddress(2), .port_id = 2, .slot_id = 2, .deadline = tsc_clock.afterMilliseconds(1_000) };
    const transfer = outstanding_transfer.?;
    try fixture.portEvent(false);
    try submitNextPortAction(&fixture);
    try fixture.finishStop();
    try std.testing.expectEqualDeep(transfer, outstanding_transfer.?);
    try submitNextPortAction(&fixture);
    try fixture.finishStop();
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.CommandKind.disable_slot, outstanding_command.?.kind);
    try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(outstanding_command.?, 1)});
    try std.testing.expectEqualDeep(transfer, outstanding_transfer.?);
}

test "xHCI hotplug rejects unordered duplicate and unowned stopped events" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    try fixture.portEvent(false);
    try submitNextPortAction(&fixture);
    const command = outstanding_command.?;
    try fixture.endpointState(1, .stopped);
    try std.testing.expectError(error.CommandRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(command, 1)), &fixture));
    const ring = try active_dma_plan.?.arena.controlTransferRingAddress(1);
    try std.testing.expectError(error.TrbRingStateInvalid, handleControlTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(ring + 1, 1, 27)), &fixture));
    try std.testing.expectError(error.TrbRingStateInvalid, handleInterruptTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(ring, 3, 27)), &fixture));
    const stopped = xhci.decodeEvent(HotplugTestFixture.transferEvent(ring, 1, 27));
    try handleControlTransferCompletion(stopped, &fixture);
    try std.testing.expectError(error.CommandRingStateInvalid, handleControlTransferCompletion(stopped, &fixture));
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
    try handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(command, 1)), &fixture);
}

test "xHCI hotplug unowned endpoint errors cannot authorize Reset or Disable" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    try fixture.portEvent(false);
    try fixture.endpointState(1, .halted);
    try std.testing.expectError(error.CommandRingStateInvalid, submitNextPortAction(&fixture));
    try fixture.endpointState(1, .error_state);
    try std.testing.expectError(error.CommandRingStateInvalid, submitNextPortAction(&fixture));
    const context = try active_dma_plan.?.arena.deviceContextAddress(1);
    const offset = active_capabilities.?.context_size.byteCount();
    const alias = try active_dma_memory.aliasFor(context + offset, @sizeOf(u32));
    @as(*u32, @ptrFromInt(alias)).* = 5; // Reserved EP State remains malformed.
    try std.testing.expectError(error.EndpointContextStateInvalid, submitNextPortAction(&fixture));
    try fixture.endpointState(1, .running);
    try submitNextPortAction(&fixture);
    const command = outstanding_command.?;
    try std.testing.expectEqual(xhci.CommandKind.stop_endpoint, command.kind);
    // No EP0 TD is owned, so Context State Error cannot wait for or authorize recovery.
    try std.testing.expectError(error.CommandRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(command, 19)), &fixture));
    try std.testing.expectEqual(@as(u2, 0), fixture.states[1].endpoint_state.failed_mask);
    try std.testing.expectEqual(@as(u8, 1), fixture.states[1].slot_id);
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
}

test "xHCI hotplug reconnect resets a replacement that is not enabled" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    try fixture.portEvent(false);
    fixture.status = (1 << 17) | (1 << 9) | 1;
    try handlePortStatusChange(xhci.decodeEvent(.{ 1 << 24, 0, 1 << 24, (34 << 10) | 1 }), &fixture);
    try submitNextPortAction(&fixture);
    try fixture.finishStop();
    try submitNextPortAction(&fixture);
    try fixture.finishStop();
    try submitNextPortAction(&fixture);
    try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(outstanding_command.?, 1)});
    try std.testing.expectEqual(PortAction.reset_port, fixture.states[1].action);
    const writes = fixture.port_writes;
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(writes + 1, fixture.port_writes);
    try std.testing.expect(fixture.states[1].reset_deadline != null);
    try std.testing.expect(outstanding_command == null);
    try std.testing.expectEqual(@as(u8, 0), fixture.states[1].slot_id);
    // The real reset completion now begins a new slot lifetime.
    try fixture.portEvent(true);
    try std.testing.expectEqual(PortAction.enable_slot, fixture.states[1].action);
}

test "xHCI hotplug retains retirement across every in-flight enumeration command" {
    for ([_]xhci.CommandKind{ .enable_slot, .address_device, .evaluate_context, .configure_endpoint }) |kind| {
        var fixture = HotplugTestFixture.init();
        try fixture.activate();
        defer fixture.restore();
        const state = &fixture.states[1];
        state.interrupt_report_trb_address = 0;
        outstanding_interrupt_reports = 0;
        state.endpoint_configured = false;
        try fixture.endpointState(3, .disabled);
        switch (kind) {
            .enable_slot => {
                state.slot_id = 0;
                state.addressed = false;
                slot_to_port[1] = 0;
                try fixture.endpointState(1, .disabled);
            },
            .address_device => state.addressed = false,
            .evaluate_context => {
                state.descriptor_prefix_valid = false;
                state.device_descriptor = null;
                state.pending_endpoint_zero_max_packet_size = 32;
            },
            .configure_endpoint => {
                state.configuration_descriptor = .{ .total_length = 34, .interface_count = 1, .configuration_value = 1, .string_index = 0, .self_powered = false, .remote_wakeup = false, .max_power_milliamps = 100 };
                try fixture.endpointState(3, .running);
            },
            else => unreachable,
        }
        outstanding_command = .{ .kind = kind, .trb_address = active_dma_plan.?.ring_plan.command_ring_address, .port_id = 1, .slot_id = state.slot_id, .deadline = tsc_clock.afterMilliseconds(1_000) };
        try fixture.portEvent(false);
        try fixture.portEvent(true);
        var completion = HotplugTestFixture.commandEvent(outstanding_command.?, 1);
        completion[3] |= 1 << 24; // Enable Slot assigns the returned slot id.
        try fixture.queuedEvents(&.{completion});
        try std.testing.expect(state.retiring);
        try std.testing.expectEqual(PortAction.retire_slot, state.action);
        try std.testing.expectEqual(@as(u8, 1), state.slot_id);
        try std.testing.expect(deviceDescriptorForPort(1) == null);
        try std.testing.expect(configurationDescriptorForPort(1) == null);
        try std.testing.expect(bootKeyboardConfigurationForPort(1) == null);
        try std.testing.expect(!portConfigured(1));
        try submitNextPortAction(&fixture);
        try std.testing.expectEqual(if (kind == .enable_slot) xhci.CommandKind.disable_slot else xhci.CommandKind.stop_endpoint, outstanding_command.?.kind);
    }
}

test "xHCI hotplug drains each exact late control completion without parsing" {
    for ([_]ControlTransferKind{ .device_descriptor_prefix, .device_descriptor, .configuration_descriptor_header, .configuration_descriptor, .set_configuration, .set_boot_protocol }) |kind| {
        var fixture = HotplugTestFixture.init();
        try fixture.activate();
        defer fixture.restore();
        const status = (try active_dma_plan.?.arena.controlTransferRingAddress(1)) + 2 * xhci.TRB_BYTES;
        outstanding_transfer = .{ .kind = kind, .status_trb_address = status, .port_id = 1, .slot_id = 1, .deadline = tsc_clock.afterMilliseconds(1_000) };
        try fixture.portEvent(false);
        try fixture.queuedEvents(&.{HotplugTestFixture.transferEvent(status, 1, 1)});
        try std.testing.expect(outstanding_transfer == null);
        try std.testing.expectEqual(PortAction.retire_slot, fixture.states[1].action);
        try std.testing.expectEqual(@as(usize, 0), fixture.reports.pendingCount());
        try std.testing.expectError(error.TrbRingStateInvalid, handleControlTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(status, 1, 1)), &fixture));
    }
}

test "xHCI hotplug accepts only the owned Address Device detach failure" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    const state = &fixture.states[1];
    state.addressed = false;
    state.endpoint_configured = false;
    state.interrupt_report_trb_address = 0;
    outstanding_interrupt_reports = 0;
    try fixture.endpointState(3, .disabled);
    const command: OutstandingCommand = .{ .kind = .address_device, .trb_address = active_dma_plan.?.ring_plan.command_ring_address, .port_id = 1, .slot_id = 1, .deadline = tsc_clock.afterMilliseconds(1_000) };
    outstanding_command = command;
    fixture.status = (1 << 9) | 1 | (1 << 1) | (3 << 10);
    try std.testing.expectError(error.TrbRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(command, 4)), &fixture));
    try std.testing.expect(!state.retiring);
    fixture.status = (1 << 17) | (1 << 9); // Detach precedes its queued PSC.
    for ([_]u8{ 7, 11, 17, 19, 25 }) |code| {
        try std.testing.expectError(error.CommandRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(command, code)), &fixture));
    }
    var wrong_slot = HotplugTestFixture.commandEvent(command, 4);
    wrong_slot[3] ^= 3 << 24;
    try std.testing.expectError(error.CommandRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(wrong_slot), &fixture));
    try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(command, 4)});
    try std.testing.expect(outstanding_command == null);
    try std.testing.expect(state.retiring);
    // Default Address failure has no TD and may Disable even with idle Running EP0.
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.CommandKind.disable_slot, outstanding_command.?.kind);
}

test "xHCI hotplug released report reservation schedules a healthy waiting port" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    fixture.states[2] = fixture.states[1];
    fixture.states[2].slot_id = 2;
    fixture.states[2].interrupt_report_trb_address = 0;
    slot_to_port[2] = 2;
    for (0..fixture.reports.reports.len - 1) |_| {
        _ = try fixture.reports.publish(2, 2, fixture.states[2].boot_keyboard.?, fixture.states[2].device_descriptor.?, &.{ 0, 0, 4, 0, 0, 0, 0, 0 });
    }
    const report_trb = fixture.states[1].interrupt_report_trb_address;
    try fixture.portEvent(false);
    try std.testing.expectEqual(PortAction.none, fixture.states[2].action);
    try fixture.queuedEvents(&.{HotplugTestFixture.transferEvent(report_trb, 3, 1)});
    try std.testing.expectEqual(@as(usize, 0), outstanding_interrupt_reports);
    try std.testing.expectEqual(PortAction.post_interrupt_report, fixture.states[2].action);
    try std.testing.expectEqual(PortAction.retire_slot, fixture.states[1].action);
    try std.testing.expectEqual(fixture.reports.reports.len - 1, fixture.reports.pendingCount());
}

test "xHCI hotplug coalesced port events neither erase ownership nor extend deadlines" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    try fixture.portEvent(false);
    const deadline = fixture.states[1].reset_deadline.?;
    fixture.status &= ~@as(u32, 0x7F << 17);
    try handlePortStatusChange(xhci.decodeEvent(.{ 1 << 24, 0, 1 << 24, (34 << 10) | 1 }), &fixture);
    try std.testing.expectEqualDeep(deadline, fixture.states[1].reset_deadline.?);
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
    try std.testing.expectEqual(PortAction.retire_slot, fixture.states[1].action);
}

test "xHCI hotplug replacement can detach again before its delayed port event" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    fixture.states[1] = .{ .connected = true, .action = .reset_port };
    fixture.status = (1 << 17) | (1 << 9);
    outstanding_interrupt_reports = 0;
    slot_to_port[1] = 0;
    try submitNextPortAction(&fixture);
    try std.testing.expect(!fixture.states[1].connected);
    try std.testing.expectEqual(PortAction.none, fixture.states[1].action);
    try std.testing.expect(fixture.states[1].reset_deadline == null);
    try std.testing.expectEqual(@as(usize, 0), fixture.command_doorbells);
}

test "xHCI hotplug coalesced detach and reconnect retires the previous slot" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    _ = try fixture.reports.publish(1, 1, fixture.states[1].boot_keyboard.?, fixture.states[1].device_descriptor.?, &.{ 0, 0, 4, 0, 0, 0, 0, 0 });
    // CCS has returned to one while CSC still records the connection changes.
    try fixture.portEvent(true);
    try std.testing.expect(fixture.states[1].retiring);
    try std.testing.expect(fixture.states[1].connected);
    try std.testing.expectEqual(PortAction.retire_slot, fixture.states[1].action);
    try std.testing.expectEqual(@as(usize, 0), fixture.reports.pendingCount());
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.CommandKind.stop_endpoint, outstanding_command.?.kind);
}

test "xHCI hotplug owned report error before port event recovers through Reset" {
    for ([_]bool{ false, true }) |reconnected| {
        var fixture = HotplugTestFixture.init();
        try fixture.activate();
        defer fixture.restore();
        const report = fixture.states[1].interrupt_report_trb_address;
        try fixture.endpointState(3, .halted);
        fixture.status = (1 << 17) | (1 << 9) |
            (if (reconnected) @as(u32, 1 | (1 << 1) | (3 << 10)) else 0);
        try fixture.queuedEvents(&.{HotplugTestFixture.transferEvent(report, 3, 4)});
        try std.testing.expect(fixture.states[1].retiring);
        try std.testing.expectEqual(@as(u2, 2), fixture.states[1].endpoint_state.failed_mask);
        try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
        try std.testing.expectEqual(report, fixture.states[1].interrupt_report_trb_address);
        try std.testing.expectError(error.TrbRingStateInvalid, handleInterruptTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(report, 3, 4)), &fixture));
        try submitNextPortAction(&fixture);
        try fixture.finishStop();
        try submitNextPortAction(&fixture);
        const reset = outstanding_command.?;
        try std.testing.expectEqual(xhci.CommandKind.reset_endpoint, reset.kind);
        try std.testing.expectEqual(@as(u5, 3), reset.endpoint_id);
        try std.testing.expectError(error.CommandRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(reset, 1)), &fixture));
        try fixture.endpointState(3, .stopped);
        try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(reset, 1)});
        try std.testing.expectEqual(@as(usize, 0), outstanding_interrupt_reports);
        try std.testing.expectEqual(@as(u2, 0), fixture.states[1].endpoint_state.failed_mask);
        try submitNextPortAction(&fixture);
        try std.testing.expectEqual(xhci.CommandKind.disable_slot, outstanding_command.?.kind);
        try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(outstanding_command.?, 1)});
        try std.testing.expectEqual(if (reconnected) PortAction.enable_slot else PortAction.none, fixture.states[1].action);
        try std.testing.expectEqual(@as(usize, 0), fixture.reports.pendingCount());
    }
}

test "xHCI hotplug authenticated transfer error can race an outstanding Stop" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    try fixture.portEvent(false);
    try submitNextPortAction(&fixture);
    try fixture.finishStop();
    try submitNextPortAction(&fixture);
    const stop = outstanding_command.?;
    try std.testing.expectEqual(@as(u5, 3), stop.endpoint_id);
    try fixture.endpointState(3, .halted);
    const report = fixture.states[1].interrupt_report_trb_address;
    try fixture.queuedEvents(&.{ HotplugTestFixture.transferEvent(report, 3, 4), HotplugTestFixture.commandEvent(stop, 19) });
    try std.testing.expect(outstanding_command == null);
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
    try submitNextPortAction(&fixture);
    const reset = outstanding_command.?;
    try std.testing.expectEqual(xhci.CommandKind.reset_endpoint, reset.kind);
    try std.testing.expectError(error.CommandRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(reset, 19)), &fixture));
    try fixture.endpointState(3, .stopped);
    try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(reset, 1)});
    try std.testing.expectEqual(@as(usize, 0), outstanding_interrupt_reports);
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.CommandKind.disable_slot, outstanding_command.?.kind);
}

test "xHCI hotplug failed control TD ownership crosses Link wrap exactly" {
    for ([_]ControlTransferKind{ .device_descriptor, .set_configuration }) |kind| {
        var fixture = HotplugTestFixture.init();
        try fixture.activate();
        defer fixture.restore();
        fixture.states[1].endpoint_configured = false;
        fixture.states[1].interrupt_report_trb_address = 0;
        outstanding_interrupt_reports = 0;
        try fixture.endpointState(3, .disabled);
        const plan = active_dma_plan.?;
        const ring = try plan.arena.controlTransferRingAddress(1);
        outstanding_transfer = .{ .kind = kind, .status_trb_address = ring, .port_id = 1, .slot_id = 1, .deadline = tsc_clock.afterMilliseconds(1_000) };
        const addresses = try controlTransferTrbAddresses(outstanding_transfer.?);
        try std.testing.expectEqual(ring + (plan.arena.control_transfer_ring_trbs - 2) * xhci.TRB_BYTES, addresses[1]);
        try fixture.endpointState(1, .running); // CC4 is authoritative despite lagging output.
        fixture.status = (1 << 17) | (1 << 9);
        // Link is inside the ring but is not part of this posted TD.
        const link = ring + (plan.arena.control_transfer_ring_trbs - 1) * xhci.TRB_BYTES;
        try std.testing.expectError(error.TrbRingStateInvalid, handleControlTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(link, 1, 4)), &fixture));
        try std.testing.expect(!fixture.states[1].retiring);
        if (kind == .set_configuration) {
            try std.testing.expectError(error.TrbRingStateInvalid, handleControlTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(ring + xhci.TRB_BYTES, 1, 4)), &fixture));
            try std.testing.expectError(error.TrbRingStateInvalid, handleControlTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(addresses[2], 1, 4)), &fixture));
        }
        try fixture.queuedEvents(&.{HotplugTestFixture.transferEvent(addresses[1], 1, 4)});
        try std.testing.expect(outstanding_transfer != null);
        try submitNextPortAction(&fixture);
        const reset = outstanding_command.?;
        try std.testing.expectEqual(xhci.CommandKind.reset_endpoint, reset.kind);
        try fixture.endpointState(1, .stopped);
        try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(reset, 1)});
        try std.testing.expect(outstanding_transfer == null);
        try submitNextPortAction(&fixture);
        try std.testing.expectEqual(xhci.CommandKind.disable_slot, outstanding_command.?.kind);
    }
}

test "xHCI hotplug rejects unproven detach errors and expires retirement bounds" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    const report = fixture.states[1].interrupt_report_trb_address;
    try fixture.endpointState(3, .halted);
    fixture.status = (1 << 9) | 1 | (1 << 1) | (3 << 10); // Same lifetime, no CSC.
    try std.testing.expectError(error.TrbRingStateInvalid, handleInterruptTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(report, 3, 4)), &fixture));
    try std.testing.expect(!fixture.states[1].retiring);
    try fixture.portEvent(false);
    fixture.states[1].reset_deadline = .{ .value = .{ .start_ticks = 0, .interval_ticks = 1 } };
    try std.testing.expectEqual(@as(?PortDeadlineKind, .retirement), expiredPortDeadline(&fixture.states[1]));
    const deadline = fixture.states[1].reset_deadline.?;
    try fixture.portEvent(true);
    try std.testing.expectEqualDeep(deadline, fixture.states[1].reset_deadline.?);
    fixture.states[1].retiring = false;
    try std.testing.expectEqual(@as(?PortDeadlineKind, .reset), expiredPortDeadline(&fixture.states[1]));
}

test "xHCI hotplug changes preserve ordinary keyboard report delivery and rearming" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    const plan = active_dma_plan.?;
    const buffer = try plan.arena.interruptReportBufferAddress(1);
    const alias = try active_dma_memory.aliasFor(buffer, xhci.HID_BOOT_KEYBOARD_REPORT_BYTES);
    const bytes: *[xhci.HID_BOOT_KEYBOARD_REPORT_BYTES]u8 = @ptrFromInt(alias);
    bytes.* = .{ 2, 0, 4, 0, 0, 0, 0, 0 };
    const original_trb = fixture.states[1].interrupt_report_trb_address;
    try fixture.queuedEvents(&.{HotplugTestFixture.transferEvent(original_trb, 3, 1)});
    try std.testing.expect(!fixture.states[1].retiring);
    try std.testing.expectEqual(@as(usize, 0), outstanding_interrupt_reports);
    const report = pollKeyboardReport().?;
    try std.testing.expectEqualDeep(bytes.*, report.bytes);
    try std.testing.expectEqual(@as(u8, 1), report.port_id);
    try std.testing.expectEqual(PortAction.post_interrupt_report, fixture.states[1].action);
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
    try std.testing.expectEqual(original_trb + xhci.TRB_BYTES, fixture.states[1].interrupt_report_trb_address);
    try std.testing.expectEqual(@as(usize, 1), fixture.transfer_doorbells);
    try std.testing.expectEqual(@as(usize, 0), fixture.command_doorbells);
}

test "xHCI hotplug authoritative failed TD overrides a lagging Running context" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    const report = fixture.states[1].interrupt_report_trb_address;
    fixture.status = (1 << 17) | (1 << 9);
    // No output-context Halted update has been published yet.
    try std.testing.expectEqual(xhci.EndpointState.running, try outputEndpointState(1, 3));
    try fixture.queuedEvents(&.{HotplugTestFixture.transferEvent(report, 3, 4)});
    try std.testing.expectEqual(@as(u2, 2), fixture.states[1].endpoint_state.failed_mask);
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
    try submitNextPortAction(&fixture);
    try fixture.finishStop();
    try std.testing.expectEqual(@as(u2, 1), fixture.states[1].endpoint_state.stopped_mask);
    try submitNextPortAction(&fixture);
    const reset = outstanding_command.?;
    try std.testing.expectEqual(xhci.CommandKind.reset_endpoint, reset.kind);
    try std.testing.expectEqual(@as(u5, 3), reset.endpoint_id);
    try std.testing.expectError(error.CommandRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(reset, 1)), &fixture));
    try fixture.endpointState(3, .stopped);
    try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(reset, 1)});
    try std.testing.expectEqual(@as(u2, 3), fixture.states[1].endpoint_state.stopped_mask);
    try std.testing.expectEqual(@as(u2, 0), fixture.states[1].endpoint_state.failed_mask);
    try std.testing.expectEqual(@as(usize, 0), outstanding_interrupt_reports);
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.CommandKind.disable_slot, outstanding_command.?.kind);
}

test "xHCI hotplug Stop state error before its failed TD retains the original bound" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    try fixture.portEvent(false);
    try submitNextPortAction(&fixture);
    try fixture.finishStop();
    const planned = try nextRetirementCommand(&fixture.states[1]);
    try std.testing.expectEqual(xhci.CommandKind.stop_endpoint, planned.kind);
    try fixture.endpointState(3, .halted);
    // The same decision stays Stop when an unprocessed failure changes DMA state.
    try std.testing.expectEqual(xhci.CommandKind.stop_endpoint, planned.kind);
    try submitNextPortAction(&fixture);
    const stop = outstanding_command.?;
    try std.testing.expectEqual(xhci.CommandKind.stop_endpoint, stop.kind);
    const retirement_deadline = fixture.states[1].reset_deadline.?;
    try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(stop, 19)});
    try std.testing.expect(outstanding_command.?.state_error_seen);
    try std.testing.expectEqualDeep(stop.deadline, outstanding_command.?.deadline);
    try std.testing.expectEqualDeep(retirement_deadline, fixture.states[1].reset_deadline.?);
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
    try std.testing.expectEqual(@as(u2, 0), fixture.states[1].endpoint_state.failed_mask);
    const doorbells = fixture.command_doorbells;
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(doorbells, fixture.command_doorbells);
    try std.testing.expectError(error.CommandRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(stop, 19)), &fixture));
    try std.testing.expectError(error.CommandRingStateInvalid, handleCommandCompletion(xhci.decodeEvent(HotplugTestFixture.commandEvent(stop, 1)), &fixture));
    const report = fixture.states[1].interrupt_report_trb_address;
    try std.testing.expectError(error.CommandRingStateInvalid, handleInterruptTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(report, 3, 27)), &fixture));
    try std.testing.expectError(error.TrbRingStateInvalid, handleInterruptTransferCompletion(xhci.decodeEvent(HotplugTestFixture.transferEvent(report + xhci.TRB_BYTES, 3, 4)), &fixture));
    try std.testing.expect(outstanding_command.?.state_error_seen);
    // Waiting for the event retains the original command timeout, even though
    // its completion has already arrived.
    outstanding_command.?.deadline = .{ .value = .{ .start_ticks = 0, .interval_ticks = 1 } };
    try std.testing.expect(commandTimedOut());
    outstanding_command.?.deadline = stop.deadline;
    // The error's output-context update may still be stale in either direction.
    try fixture.endpointState(3, .running);
    try fixture.queuedEvents(&.{HotplugTestFixture.transferEvent(report, 3, 4)});
    try std.testing.expect(outstanding_command == null);
    try std.testing.expectEqual(@as(usize, 1), outstanding_interrupt_reports);
    try submitNextPortAction(&fixture);
    const reset = outstanding_command.?;
    try std.testing.expectEqual(xhci.CommandKind.reset_endpoint, reset.kind);
    try fixture.endpointState(3, .stopped);
    try fixture.queuedEvents(&.{HotplugTestFixture.commandEvent(reset, 1)});
    try std.testing.expectEqual(@as(usize, 0), outstanding_interrupt_reports);
    try submitNextPortAction(&fixture);
    try std.testing.expectEqual(xhci.CommandKind.disable_slot, outstanding_command.?.kind);
}

test "xHCI hotplug completion state masks clear before a fresh slot lifetime" {
    var fixture = HotplugTestFixture.init();
    try fixture.activate();
    defer fixture.restore();
    fixture.states[1] = .{ .connected = true, .enabled = true, .speed_id = 3, .endpoint_state = .{ .failed_mask = 3, .stopped_mask = 3 } };
    outstanding_interrupt_reports = 0;
    slot_to_port[1] = 0;
    outstanding_command = .{ .kind = .enable_slot, .trb_address = active_dma_plan.?.ring_plan.command_ring_address, .port_id = 1, .slot_id = 0, .deadline = tsc_clock.afterMilliseconds(1_000) };
    var event = HotplugTestFixture.commandEvent(outstanding_command.?, 1);
    event[3] |= 1 << 24;
    try fixture.queuedEvents(&.{event});
    try std.testing.expectEqual(@as(u2, 0), fixture.states[1].endpoint_state.failed_mask);
    try std.testing.expectEqual(@as(u2, 0), fixture.states[1].endpoint_state.stopped_mask);
    try std.testing.expectEqual(PortAction.address_device, fixture.states[1].action);
    try std.testing.expect(!fixture.states[1].retiring);
}
