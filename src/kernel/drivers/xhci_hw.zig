const std = @import("std");
const console = @import("../utils/console.zig");
const endian = @import("../utils/endian.zig");
const mmio_windows = @import("../memory/mmio_windows.zig");
const paging = @import("../memory/paging64.zig");
const x2apic = @import("../interrupts/x2apic.zig");
const intel_vtd = @import("../platform/intel_vtd.zig");
const tsc_clock = @import("../timer/tsc_clock.zig");
const pci = @import("pci.zig");
const xhci = @import("xhci.zig");

const PAGE_BYTES = mmio_windows.PAGE_BYTES;
const OWNERSHIP_TIMEOUT_MILLISECONDS: u64 = 1_000;
const PORT_RESET_TIMEOUT_MILLISECONDS: u64 = 1_000;
const COMMAND_TIMEOUT_MILLISECONDS: u64 = 1_000;
const CONTROL_TRANSFER_TIMEOUT_MILLISECONDS: u64 = 1_000;
const OS_OWNED_BYTE_OFFSET: usize = 3;
const PORT_RESET_COMPLETION_CHANGE_MASK: u7 = (1 << 2) | (1 << 4);

pub const INTERRUPT_VECTOR: u8 = 67;
pub const PORT_RUNTIME_STATE_SIZE_CEILING_BYTES: usize = 104;
pub const CONTROLLER_RUNTIME_STATE_MAX_FRAME_COUNT: usize = 7;
pub const COLOCATED_BOOT_KEYBOARD_REPORT_STATE = true;
pub const COLOCATED_SUPPORTED_PROTOCOL_STATE = true;
pub const INTERRUPT_STATE_USES_PROTOCOL_ORDERING = true;

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

var active_capabilities: ?xhci.CapabilityRegisters = null;
var active_protocols: ?*const xhci.SupportedProtocols = null;
var active_legacy_ownership: ?xhci.LegacyOwnership = null;
var active_controller_reset = false;
var active_enabled_slots: u8 = 0;
var active_device: pci.PCIDevice = undefined;
var active_dma_plan: ?xhci.ControllerDmaPlan = null;
var active_dma_base: u32 = 0;
var active_dma_frame_count: u32 = 0;
var active_dma_windows: [xhci.MAX_CONTROLLER_DMA_REGIONS]intel_vtd.DmaWindow = undefined;
var active_dma_window_count: usize = 0;
var active_bar_address: usize = 0;
var active = false;
var event_consumer = xhci.EventRingConsumer{};
var command_producer = xhci.TrbRingProducer{};
var control_producers = [_]xhci.TrbRingProducer{.{}} ** (xhci.MAX_DEVICE_SLOTS + 1);
var interrupt_producers = [_]xhci.TrbRingProducer{.{}} ** (xhci.MAX_DEVICE_SLOTS + 1);
var slot_to_port = [_]u8{0} ** (xhci.MAX_DEVICE_SLOTS + 1);
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

fn controllerActive() bool {
    return @atomicLoad(bool, &active, .acquire);
}

fn publishControllerActive(value: bool) void {
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
};

const PortRuntimeState = struct {
    connected: bool = false,
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
    base: u32,
    frame_count: u32,
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
var active_controller_runtime_state_base: u32 = 0;
var active_controller_runtime_state_frame_count: u32 = 0;
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
    const base = paging.allocLowIdentityFrames(frame_count) orelse
        return error.ControllerRuntimeStateAllocationFailed;
    const allocation_bytes = @as(usize, frame_count) * PAGE_BYTES;
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
        .base = base,
        .frame_count = frame_count,
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
    active_bar_address = 0;
    publishControllerActive(false);
    event_consumer = .{};
    command_producer = .{};
    control_producers = [_]xhci.TrbRingProducer{.{}} ** (xhci.MAX_DEVICE_SLOTS + 1);
    interrupt_producers = [_]xhci.TrbRingProducer{.{}} ** (xhci.MAX_DEVICE_SLOTS + 1);
    slot_to_port = [_]u8{0} ** (xhci.MAX_DEVICE_SLOTS + 1);
    active_keyboard_reports = null;
    outstanding_interrupt_reports = 0;
    ports = empty_port_runtime_states[0..];
    active_controller_runtime_state_base = 0;
    active_controller_runtime_state_frame_count = 0;
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
    errdefer if (!retain_controller_runtime_state) paging.releaseLowIdentityFrames(
        controller_runtime_state.base,
        controller_runtime_state.frame_count,
    ) catch {};
    const dma_frame_count = try xhci.controllerDmaFrameCount(capabilities, enabled_slots);
    const dma_base = paging.allocLowIdentityFrames(dma_frame_count) orelse return error.DmaAllocationFailed;
    var retain_dma_frames = false;
    errdefer if (!retain_dma_frames) paging.releaseLowIdentityFrames(dma_base, dma_frame_count) catch {};
    const dma_plan = try xhci.planControllerDma(capabilities, enabled_slots, dma_base);
    if (try dma_plan.frameCount() > dma_frame_count) return error.DmaIsolationPlanInvalid;
    const dma_bytes = std.math.cast(usize, dma_plan.total_bytes) orelse
        return error.DmaIsolationPlanInvalid;
    const dma_memory: [*]u8 = @ptrFromInt(dma_base);
    try xhci.initializeControllerDma(dma_plan, dma_memory[0..dma_bytes]);
    publishDmaStructures();
    try xhci.programControllerDmaRegisters(capabilities, dma_plan, &reader);
    const dma_window_count = try buildDmaWindows(dma_plan, &active_dma_windows);

    active_device = device_info;
    active_dma_plan = dma_plan;
    active_dma_base = dma_base;
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
    active_controller_runtime_state_base = controller_runtime_state.base;
    active_controller_runtime_state_frame_count = controller_runtime_state.frame_count;
    retain_controller_runtime_state = true;
    retain_dma_frames = true;
    return capabilities;
}

pub fn validated() bool {
    const capabilities = active_capabilities orelse return false;
    const ownership = active_legacy_ownership orelse return false;
    return active_protocols != null and
        ownership != .firmware_released and
        active_controller_reset and
        active_enabled_slots != 0 and
        active_controller_runtime_state_base != 0 and
        active_controller_runtime_state_frame_count == controllerRuntimeStateFrameCountFor(capabilities.max_ports) and
        active_keyboard_reports != null and
        ports.len == @as(usize, capabilities.max_ports) + 1 and
        active_dma_plan != null and
        active_dma_window_count != 0;
}

pub fn probedCapabilities() ?xhci.CapabilityRegisters {
    return active_capabilities;
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
    return active_dma_base;
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
        x2apic.localId(),
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
    control_producers = [_]xhci.TrbRingProducer{.{}} ** (xhci.MAX_DEVICE_SLOTS + 1);
    interrupt_producers = [_]xhci.TrbRingProducer{.{}} ** (xhci.MAX_DEVICE_SLOTS + 1);
    slot_to_port = [_]u8{0} ** (xhci.MAX_DEVICE_SLOTS + 1);
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
        switch (event.kind) {
            .port_status_change => {
                handlePortStatusChange(event, &reader) catch {
                    containFailure("ZIGOS:XHCI:HW:PORT_EVENT_CONTAINED\n");
                    return processed + 1;
                };
                port_status_change_count +%= 1;
            },
            .command_completion => {
                handleCommandCompletion(event) catch {
                    containFailure("ZIGOS:XHCI:HW:COMMAND_EVENT_CONTAINED\n");
                    return processed + 1;
                };
                command_completion_count +%= 1;
            },
            .transfer => {
                const result = if (event.endpoint_id == xhci.ENDPOINT_ZERO_DCI)
                    handleControlTransferCompletion(event)
                else
                    handleInterruptTransferCompletion(event);
                result catch {
                    containFailure("ZIGOS:XHCI:HW:TRANSFER_EVENT_CONTAINED\n");
                    return processed + 1;
                };
                transfer_completion_count +%= 1;
            },
            .host_controller, .vendor_defined, .unknown => {
                containFailure("ZIGOS:XHCI:HW:CONTROLLER_EVENT_CONTAINED\n");
                return processed + 1;
            },
            .bandwidth_request,
            .doorbell,
            .device_notification,
            .mfindex_wrap,
            => {},
        }
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
    if (!state.endpoint_configured or state.slot_id != report.slot_id or
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
    return ports[port_id].device_descriptor;
}

pub fn configurationDescriptorForPort(port_id: u8) ?xhci.UsbConfigurationDescriptor {
    if (!controllerActive()) return null;
    const capabilities = active_capabilities orelse return null;
    if (port_id == 0 or port_id > capabilities.max_ports) return null;
    return ports[port_id].configuration_descriptor;
}

pub fn bootKeyboardConfigurationForPort(port_id: u8) ?xhci.UsbBootKeyboardConfiguration {
    if (!controllerActive()) return null;
    const capabilities = active_capabilities orelse return null;
    if (port_id == 0 or port_id > capabilities.max_ports) return null;
    return ports[port_id].boot_keyboard;
}

pub fn portConfigured(port_id: u8) bool {
    if (!controllerActive()) return false;
    const capabilities = active_capabilities orelse return false;
    if (port_id == 0 or port_id > capabilities.max_ports) return false;
    return ports[port_id].endpoint_configured;
}

pub fn handledInterruptCount() u64 {
    return @atomicLoad(u64, &interrupt_count, .monotonic);
}

fn clearPortDescriptorState(state: *PortRuntimeState) void {
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
        if (!state.connected or !state.enabled or !state.addressed or
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

fn handlePortStatusChange(event: xhci.Event, reader: *ExtendedCapabilityReader) Error!void {
    const capabilities = active_capabilities orelse return error.InvalidPortStatus;
    const protocols = active_protocols orelse return error.MissingSupportedProtocols;
    if (!event.succeeded() or event.port_id == 0 or event.port_id > capabilities.max_ports) {
        return error.InvalidPortStatus;
    }
    const protocol = protocols.forPort(event.port_id) orelse return error.MissingPortProtocol;
    const register_offset = try xhci.portRegisterOffset(capabilities, event.port_id);
    const raw_status = reader.readReg32(register_offset);
    const status = xhci.decodePortStatus(raw_status);
    if (status.change_bits == 0 or status.over_current) return error.InvalidPortStatus;

    const state = &ports[event.port_id];
    state.connected = status.connected;
    state.enabled = status.enabled;
    if (!status.connected) {
        reader.writeReg32(register_offset, xhci.portStatusAcknowledge(raw_status));
        state.addressed = false;
        if (state.interrupt_report_trb_address != 0) {
            if (outstanding_interrupt_reports == 0) return error.TrbRingStateInvalid;
            outstanding_interrupt_reports -= 1;
        }
        keyboardReports().clearPort(event.port_id);
        clearPortDescriptorState(state);
        scheduleUnarmedInterruptReports();
        state.speed_id = 0;
        state.reset_deadline = null;
        state.action = if (state.slot_id != 0) .disable_slot else .none;
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

fn handleCommandCompletion(event: xhci.Event) Error!void {
    const command = outstanding_command orelse return error.CommandRingStateInvalid;
    if (!event.succeeded() or event.parameter != command.trb_address) {
        return error.CommandRingStateInvalid;
    }
    const capabilities = active_capabilities orelse return error.CommandRingStateInvalid;
    const state = &ports[command.port_id];
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
            state.action = if (state.connected and state.enabled) .address_device else .disable_slot;
        },
        .address_device => {
            if (command.slot_id == 0 or event.slot_id != command.slot_id or
                state.slot_id != command.slot_id or state.addressed)
            {
                return error.InvalidDeviceSlot;
            }
            state.addressed = state.connected and state.enabled;
            if (state.addressed and state.endpoint_zero_max_packet_size == 0) {
                return error.InvalidInputContext;
            }
            state.action = if (state.addressed) .read_device_descriptor_prefix else .disable_slot;
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
            state.action = if (state.connected and state.enabled) .enable_slot else .none;
        },
    }
    outstanding_command = null;
}

fn handleControlTransferCompletion(event: xhci.Event) Error!void {
    const transfer = outstanding_transfer orelse return error.TrbRingStateInvalid;
    if (!event.succeeded() or event.parameter != transfer.status_trb_address or
        event.slot_id != transfer.slot_id or
        event.endpoint_id != xhci.ENDPOINT_ZERO_DCI or
        event.event_data or event.transfer_length != 0)
    {
        return error.TrbRingStateInvalid;
    }
    const protocols = active_protocols orelse return error.MissingSupportedProtocols;
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    const state = &ports[transfer.port_id];
    if (!state.connected or !state.enabled or !state.addressed or
        state.slot_id != transfer.slot_id)
    {
        return error.InvalidDeviceSlot;
    }
    const source: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(
        plan.arena.enumeration_buffer_address,
    )));
    const first_byte: *const u8 = @ptrFromInt(@as(usize, @intCast(
        plan.arena.enumeration_buffer_address,
    )));
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

fn handleInterruptTransferCompletion(event: xhci.Event) Error!void {
    if (event.slot_id == 0 or event.slot_id > active_enabled_slots) {
        return error.InvalidDeviceSlot;
    }
    const port_id = slot_to_port[event.slot_id];
    const capabilities = active_capabilities orelse return error.TrbRingStateInvalid;
    if (port_id == 0 or port_id > capabilities.max_ports) return error.InvalidDeviceSlot;
    const state = &ports[port_id];
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
    const source: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(buffer_address)));
    const first_byte: *const u8 = @ptrFromInt(@as(usize, @intCast(buffer_address)));
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

fn lifecycleTimedOut() bool {
    if (outstanding_command) |command| {
        if (command.deadline.expired()) {
            containFailure("ZIGOS:XHCI:HW:COMMAND_TIMEOUT_CONTAINED\n");
            return true;
        }
    }
    if (outstanding_transfer) |transfer| {
        if (transfer.deadline.expired()) {
            containFailure("ZIGOS:XHCI:HW:TRANSFER_TIMEOUT_CONTAINED\n");
            return true;
        }
    }
    const capabilities = active_capabilities orelse return false;
    var port_id: u16 = 1;
    while (port_id <= capabilities.max_ports) : (port_id += 1) {
        if (ports[port_id].reset_deadline) |deadline| {
            if (deadline.expired()) {
                containFailure("ZIGOS:XHCI:HW:PORT_RESET_TIMEOUT_CONTAINED\n");
                return true;
            }
        }
    }
    return false;
}

fn submitNextPortAction(reader: *ExtendedCapabilityReader) Error!void {
    if (outstanding_command != null or outstanding_transfer != null) return;
    const capabilities = active_capabilities orelse return error.CommandRingStateInvalid;
    const protocols = active_protocols orelse return error.MissingSupportedProtocols;
    const plan = active_dma_plan orelse return error.CommandRingStateInvalid;
    var inspected: u16 = 0;
    while (inspected < capabilities.max_ports) : (inspected += 1) {
        const port_id: u8 = @intCast(next_port_scan);
        next_port_scan = if (next_port_scan >= capabilities.max_ports) 1 else next_port_scan + 1;
        const state = &ports[port_id];
        if (state.action == .none) continue;
        switch (state.action) {
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

        const kind: xhci.CommandKind = switch (state.action) {
            .none => unreachable,
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
        };
        const words = switch (kind) {
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
    const trb: [*]volatile u32 = @ptrFromInt(@as(usize, @intCast(trb_address)));
    trb[0] = words[0];
    trb[1] = words[1];
    trb[2] = words[2];
    trb[3] = words[3];
    if (try producer.advance(ring_trbs)) {
        const link_address = try producer.linkAddress(ring_address, ring_trbs);
        const link: [*]volatile u32 = @ptrFromInt(@as(usize, @intCast(link_address)));
        link[3] = xhci.ringLinkControl(cycle_state);
    }
    return trb_address;
}

fn submitInterruptReportTransfer(
    port_id: u8,
    state: *PortRuntimeState,
    reader: *ExtendedCapabilityReader,
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
    const buffer: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(buffer_address)));
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
    reader: *ExtendedCapabilityReader,
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
    const buffer: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(
        plan.arena.enumeration_buffer_address,
    )));
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
    reader: *ExtendedCapabilityReader,
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
    reader: *ExtendedCapabilityReader,
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
    const input_context: [*]u8 = @ptrFromInt(@as(usize, @intCast(
        plan.arena.input_context_address,
    )));
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
    const input_context: [*]u8 = @ptrFromInt(@as(usize, @intCast(
        plan.arena.input_context_address,
    )));
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
    const input_context: [*]u8 = @ptrFromInt(@as(usize, @intCast(
        plan.arena.input_context_address,
    )));
    try xhci.initializeEvaluateEndpointZeroInputContext(
        capabilities.context_size,
        state.pending_endpoint_zero_max_packet_size,
        input_context[0..plan.arena.input_context_bytes],
    );
}

fn resetSlotTransferRings(slot_id: u8) Error!void {
    const plan = active_dma_plan orelse return error.TrbRingStateInvalid;
    const dma_bytes = std.math.cast(usize, plan.total_bytes) orelse
        return error.DmaBufferTooSmall;
    const memory: [*]u8 = @ptrFromInt(@as(usize, @intCast(plan.base_address)));
    try xhci.resetTransferRing(
        plan,
        memory[0..dma_bytes],
        try plan.arena.controlTransferRingAddress(slot_id),
        plan.arena.control_transfer_ring_trbs,
    );
    try xhci.resetTransferRing(
        plan,
        memory[0..dma_bytes],
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
    @as(*volatile u64, @ptrFromInt(@as(usize, @intCast(entry_address)))).* = address;
    publishDmaStructures();
}

fn clearDeviceContext(slot_id: u8) Error!void {
    const plan = active_dma_plan orelse return error.CommandRingStateInvalid;
    const address = try plan.arena.deviceContextAddress(slot_id);
    const bytes: usize = @intCast(plan.arena.device_context_stride);
    const context: [*]u8 = @ptrFromInt(@as(usize, @intCast(address)));
    @memset(context[0..bytes], 0);
    publishDmaStructures();
}

fn currentEventReady() bool {
    const plan = active_dma_plan orelse return false;
    const control_address = plan.ring_plan.event_ring_address +
        @as(u64, event_consumer.dequeue_index) * xhci.TRB_BYTES +
        3 * @sizeOf(u32);
    const control = @as(*volatile u32, @ptrFromInt(@as(usize, @intCast(control_address)))).*;
    return event_consumer.ready(control);
}

fn readCurrentEvent() ?[4]u32 {
    const plan = active_dma_plan orelse return null;
    const trb_address = plan.ring_plan.event_ring_address +
        @as(u64, event_consumer.dequeue_index) * xhci.TRB_BYTES;
    const trb: [*]volatile u32 = @ptrFromInt(@as(usize, @intCast(trb_address)));
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
    control_producers = [_]xhci.TrbRingProducer{.{}} ** (xhci.MAX_DEVICE_SLOTS + 1);
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
    var snapshot = [_]u8{0} ** xhci.CAPABILITY_REGISTERS_BYTES;
    var offset: usize = 0;
    while (offset < snapshot.len) : (offset += @sizeOf(u32)) {
        const value = @as(*volatile u32, @ptrFromInt(base + offset)).*;
        endian.writeU32Le(snapshot[offset..][0..@sizeOf(u32)], value);
    }
    return snapshot;
}

fn validTestSnapshot() [xhci.CAPABILITY_REGISTERS_BYTES]u8 {
    var snapshot = [_]u8{0} ** xhci.CAPABILITY_REGISTERS_BYTES;
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
    try std.testing.expectEqual(@as(usize, 7), count);
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
