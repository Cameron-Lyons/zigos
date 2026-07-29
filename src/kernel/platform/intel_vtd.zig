const std = @import("std");
const builtin = @import("builtin");
const pci = @import("../drivers/pci.zig");
const paging = @import("../memory/paging64.zig");
const dmar = @import("dmar.zig");

const PAGE_SIZE: u32 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;
const MANAGED_DMA_LIMIT: u64 = 128 * 1024 * 1024;
const TABLE_ENTRY_COUNT: usize = 512;
const TABLE_PAGE_COUNT: u32 = 24;
const INTERRUPT_TABLE_PAGE_COUNT: u32 = 1;
const ROOT_PAGE: u32 = 0;
const FIRST_DYNAMIC_TABLE_PAGE: u32 = 1;
const MAX_DMA_DOMAINS: usize = 2;
const MAX_DMA_WINDOWS_PER_DOMAIN: usize = 8;
const INTERRUPT_TABLE_PAGE: u32 = TABLE_PAGE_COUNT;
const FIRST_INVALIDATION_QUEUE_PAGE: u32 = INTERRUPT_TABLE_PAGE + INTERRUPT_TABLE_PAGE_COUNT;
const INTERRUPT_REMAP_ENTRY_COUNT: usize = PAGE_SIZE / 16;
const INVALIDATION_QUEUE_TAIL: u64 = 32;
const INVALIDATION_STATUS_OFFSET: u32 = PAGE_SIZE - @sizeOf(u32);
const INVALIDATION_STATUS_VALUE: u32 = 0x5644_4952;
const SECOND_STAGE_READ: u64 = 1 << 0;
const SECOND_STAGE_WRITE: u64 = 1 << 1;
const PRESENT: u64 = 1;
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const FIRST_DOMAIN_ID: u16 = 1;

const KERNEL_VTD_MMIO_VIRTUAL_BASE: usize = 0xFFFF_8000_3000_0000;
const UNIT_MMIO_STRIDE: usize = 0x4000;
const UNIT_IOTLB_PAGE_OFFSET: usize = 0x1000;
const UNIT_FAULT_PAGE_OFFSET: usize = 0x2000;
const MAX_FAULT_RECORD_PAGES: usize = 2;

const REG_VERSION: usize = 0x000;
const REG_CAPABILITY: usize = 0x008;
const REG_EXTENDED_CAPABILITY: usize = 0x010;
const REG_GLOBAL_COMMAND: usize = 0x018;
const REG_GLOBAL_STATUS: usize = 0x01C;
const REG_ROOT_TABLE_ADDRESS: usize = 0x020;
const REG_CONTEXT_COMMAND: usize = 0x028;
const REG_FAULT_STATUS: usize = 0x034;
const REG_FAULT_EVENT_CONTROL: usize = 0x038;
const REG_INVALIDATION_QUEUE_HEAD: usize = 0x080;
const REG_INVALIDATION_QUEUE_TAIL: usize = 0x088;
const REG_INVALIDATION_QUEUE_ADDRESS: usize = 0x090;
const REG_INTERRUPT_REMAP_TABLE_ADDRESS: usize = 0x0B8;
const INTERRUPT_REMAP_EXTENDED_MODE_ENABLE: u64 = 1 << 11;

const GLOBAL_TRANSLATION_ENABLE: u32 = 1 << 31;
const GLOBAL_SET_ROOT_TABLE_POINTER: u32 = 1 << 30;
const GLOBAL_QUEUED_INVALIDATION_ENABLE: u32 = 1 << 26;
const GLOBAL_INTERRUPT_REMAP_ENABLE: u32 = 1 << 25;
const GLOBAL_SET_INTERRUPT_REMAP_TABLE_POINTER: u32 = 1 << 24;
const GLOBAL_COMPATIBILITY_FORMAT_INTERRUPT: u32 = 1 << 23;
const GLOBAL_COMMAND_STATUS_MASK: u32 = 0x96FF_FFFF;
const CONTEXT_INVALIDATE: u64 = 1 << 63;
const CONTEXT_GLOBAL_INVALIDATION: u64 = 1 << 61;
const CONTEXT_ACTUAL_GRANULARITY_MASK: u64 = 0b11 << 59;
const IOTLB_INVALIDATE: u64 = 1 << 63;
const IOTLB_GLOBAL_INVALIDATION: u64 = 1 << 60;
const IOTLB_ACTUAL_GRANULARITY_MASK: u64 = 0b11 << 57;
const COMMAND_SPIN_LIMIT: u64 = 50_000_000;
const FAULT_EVENT_INTERRUPT_MASK: u32 = 1 << 31;
const FAULT_STATUS_INDEX_SHIFT: u5 = 8;
const FAULT_STATUS_INDEX_MASK: u32 = 0xFF;
const FAULT_STATUS_INVALIDATION_ERRORS: u32 = (1 << 6) | (1 << 5) | (1 << 4);
const FAULT_STATUS_PRIMARY_PENDING: u32 = 1 << 1;
const FAULT_STATUS_PRIMARY_OVERFLOW: u32 = 1 << 0;
const FAULT_RECORD_PRESENT: u64 = 1 << 63;

const CAP_ENHANCED_SRTP: u64 = 1 << 63;
const CAP_ENHANCED_SIRTP: u64 = 1 << 62;
const CAP_FAULT_RECORD_COUNT_SHIFT: u6 = 40;
const CAP_FAULT_RECORD_COUNT_MASK: u64 = 0xFF;
const CAP_FAULT_RECORD_OFFSET_SHIFT: u6 = 24;
const CAP_FAULT_RECORD_OFFSET_MASK: u64 = 0x3FF;
const CAP_MGAW_SHIFT: u6 = 16;
const CAP_MGAW_MASK: u64 = 0x3F;
const CAP_SAGAW_SHIFT: u6 = 8;
const CAP_SAGAW_MASK: u64 = 0x1F;
const ECAP_IOTLB_REGISTER_OFFSET_SHIFT: u6 = 8;
const ECAP_IOTLB_REGISTER_OFFSET_MASK: u64 = 0x3FF;
const ECAP_PAGE_WALK_COHERENT: u64 = 1 << 0;
const ECAP_QUEUED_INVALIDATION: u64 = 1 << 1;
const ECAP_INTERRUPT_REMAP: u64 = 1 << 3;
const ECAP_EXTENDED_INTERRUPT_MODE: u64 = 1 << 4;

const PageTable = [TABLE_ENTRY_COUNT]u64;
const Tables = [TABLE_PAGE_COUNT]PageTable;
const InterruptTable = [INTERRUPT_REMAP_ENTRY_COUNT][2]u64;

pub const DmaWindow = struct {
    base: u32,
    length: u32 = PAGE_SIZE,
    device_readable: bool,
    device_writable: bool,
};

pub const DmaDomain = struct {
    device: pci.PCIDevice,
    windows: []const DmaWindow,
};

pub const Error = error{
    AlreadyEnabled,
    FirmwarePolicyUnsupported,
    ActiveBusMaster,
    ActiveInterruptSource,
    InvalidDmaWindow,
    UnsupportedHardwareVersion,
    UnsupportedAddressWidth,
    NonCoherentPageWalk,
    InterruptRemappingUnsupported,
    ExtendedInterruptModeUnsupported,
    InvalidRegisterRange,
    InvalidFaultRecordRange,
    FirmwareRemappingActive,
    TableAllocationFailed,
    CommandTimeout,
    CommandRejected,
    InvalidationQueueError,
    DmaFaultMissing,
    UnexpectedDmaFault,
};

const AddressWidth = enum(u3) {
    bits39 = 1,
    bits48 = 2,
};

const UnitRegisters = struct {
    index: u8,
    base: usize,
    iotlb: usize,
    fault_records: usize,
    fault_record_count: u16,
    capability: u64,
    enhanced_srtp: bool,
    enhanced_sirtp: bool,
};

pub const RequestType = enum(u2) {
    write = 0,
    page_request = 1,
    read = 2,
    atomic = 3,
};

pub const FaultRecord = struct {
    unit_index: u8,
    source_id: u16,
    reason: u8,
    request_type: RequestType,
    info: u64,

    pub fn provesBlockedWrite(self: FaultRecord, expected_requester: u16, expected_address: u32) bool {
        return self.source_id == expected_requester and
            self.reason < 0x20 and
            self.request_type == .write and
            self.info == (@as(u64, expected_address) & ~PAGE_MASK);
    }
};

var enabled = false;
var interrupt_remapping_enabled = false;
var fault_monitoring_enabled = false;
var protected_requester_ids: [MAX_DMA_DOMAINS]u16 = [_]u16{0} ** MAX_DMA_DOMAINS;
var protected_requester_count: usize = 0;
var active_units: [dmar.MAX_REMAPPING_UNITS]UnitRegisters = undefined;
var active_unit_count: usize = 0;
var blocked_dma_proof: ?FaultRecord = null;
var deferred_faults: [MAX_DMA_DOMAINS]?FaultRecord = [_]?FaultRecord{null} ** MAX_DMA_DOMAINS;

pub fn dmaIsolationEnabled() bool {
    return enabled;
}

pub fn interruptIsolationEnabled() bool {
    return enabled and interrupt_remapping_enabled;
}

pub fn faultMonitoringEnabled() bool {
    return enabled and fault_monitoring_enabled;
}

pub fn blockedDmaProof() ?FaultRecord {
    return blocked_dma_proof;
}

pub fn pollFault() Error!?FaultRecord {
    if (!faultMonitoringEnabled()) return null;
    const source_id = protectedRequesterId() orelse return error.UnexpectedDmaFault;
    return pollFaultForSource(source_id);
}

pub fn pollFaultForDevice(device_info: pci.PCIDevice) Error!?FaultRecord {
    if (!faultMonitoringEnabled()) return null;
    const source_id = requesterId(device_info);
    if (protectedRequesterIndex(source_id) == null) return error.UnexpectedDmaFault;
    return pollFaultForSource(source_id);
}

fn protectedRequesterId() ?u16 {
    if (!enabled or protected_requester_count == 0) return null;
    return protected_requester_ids[0];
}

pub fn requesterProtected(device_info: pci.PCIDevice) bool {
    if (!enabled) return false;
    const source_id = requesterId(device_info);
    for (protected_requester_ids[0..protected_requester_count]) |protected| {
        if (protected == source_id) return true;
    }
    return false;
}

pub fn enforceDevices(
    summary: *const dmar.Summary,
    domains: []const DmaDomain,
) Error!void {
    if (enabled) return error.AlreadyEnabled;
    if (!summary.productionEnforcementReady()) return error.FirmwarePolicyUnsupported;
    if (pci.bootBusMasterCount() != 0) return error.ActiveBusMaster;
    if (pci.bootLegacyInterruptCount() != 0 or
        (pci.bootMessageSignaledInterruptCount() catch return error.ActiveInterruptSource) != 0)
    {
        return error.ActiveInterruptSource;
    }
    try validateDomains(domains);

    var units: [dmar.MAX_REMAPPING_UNITS]UnitRegisters = undefined;
    var common_sagaw: u8 = CAP_SAGAW_MASK;
    for (summary.units(), 0..) |unit, index| {
        const registers = try probeUnit(unit, index, summary.host_address_width);
        units[index] = registers;
        common_sagaw &= @intCast((registers.capability >> CAP_SAGAW_SHIFT) & CAP_SAGAW_MASK);
    }
    const address_width = chooseAddressWidth(common_sagaw) orelse
        return error.UnsupportedAddressWidth;

    const retained_page_count = FIRST_INVALIDATION_QUEUE_PAGE +
        @as(u32, @intCast(summary.remapping_unit_count));
    const table_base = paging.alloc_frames(retained_page_count) orelse
        return error.TableAllocationFailed;
    var may_release_tables = true;
    errdefer if (may_release_tables) paging.release_frames(table_base, retained_page_count) catch {};
    const tables: *Tables = @ptrFromInt(table_base);
    try populateTables(tables, table_base, domains, address_width);
    const interrupt_table_base = tablePagePhysical(table_base, INTERRUPT_TABLE_PAGE);
    const interrupt_table: *InterruptTable = @ptrFromInt(interrupt_table_base);
    @memset(std.mem.asBytes(interrupt_table), 0);
    for (0..summary.remapping_unit_count) |index| {
        const queue_base = tablePagePhysical(
            table_base,
            FIRST_INVALIDATION_QUEUE_PAGE + @as(u32, @intCast(index)),
        );
        @memset(@as([*]u8, @ptrFromInt(queue_base))[0..PAGE_SIZE], 0);
    }
    publishTables();

    // From this point onward a unit may retain the table pointer even if a later
    // unit fails. Keep the frames permanently reserved on every such failure.
    may_release_tables = false;
    for (units[0..summary.remapping_unit_count], 0..) |unit, index| {
        try programUnit(unit, table_base);
        try armFaultMonitoring(unit);
        try programInterruptRemapping(
            unit,
            interrupt_table_base,
            tablePagePhysical(
                table_base,
                FIRST_INVALIDATION_QUEUE_PAGE + @as(u32, @intCast(index)),
            ),
        );
        active_units[index] = unit;
    }

    protected_requester_count = domains.len;
    for (domains, 0..) |domain, index| {
        protected_requester_ids[index] = requesterId(domain.device);
    }
    active_unit_count = summary.remapping_unit_count;
    interrupt_remapping_enabled = true;
    fault_monitoring_enabled = true;
    blocked_dma_proof = null;
    deferred_faults = [_]?FaultRecord{null} ** MAX_DMA_DOMAINS;
    enabled = true;
}

fn validateDomains(domains: []const DmaDomain) Error!void {
    if (domains.len == 0 or domains.len > MAX_DMA_DOMAINS) return error.InvalidDmaWindow;
    for (domains, 0..) |domain, index| {
        try validateWindows(domain.windows);
        const source_id = requesterId(domain.device);
        for (domains[0..index]) |prior| {
            if (requesterId(prior.device) == source_id) return error.InvalidDmaWindow;
            for (domain.windows) |window| {
                const window_end = @as(u64, window.base) + window.length;
                for (prior.windows) |prior_window| {
                    const prior_end = @as(u64, prior_window.base) + prior_window.length;
                    if (@as(u64, window.base) < prior_end and
                        @as(u64, prior_window.base) < window_end)
                    {
                        return error.InvalidDmaWindow;
                    }
                }
            }
        }
    }
}

fn validateWindows(windows: []const DmaWindow) Error!void {
    if (windows.len == 0 or windows.len > MAX_DMA_WINDOWS_PER_DOMAIN) return error.InvalidDmaWindow;
    for (windows, 0..) |window, index| {
        const window_end = @as(u64, window.base) + window.length;
        if (window.length == 0 or window.length % PAGE_SIZE != 0 or window.base % PAGE_SIZE != 0 or
            (!window.device_readable and !window.device_writable) or
            window_end > MANAGED_DMA_LIMIT)
        {
            return error.InvalidDmaWindow;
        }
        for (windows[0..index]) |prior| {
            const prior_end = @as(u64, prior.base) + prior.length;
            if (@as(u64, window.base) < prior_end and @as(u64, prior.base) < window_end) {
                return error.InvalidDmaWindow;
            }
        }
    }
}

fn chooseAddressWidth(sagaw: u8) ?AddressWidth {
    // The current physical aperture fits comfortably in 39 bits. Prefer the
    // three-level walk to remove one dependent memory access from every miss.
    if ((sagaw & (@as(u8, 1) << @intFromEnum(AddressWidth.bits39))) != 0) return .bits39;
    if ((sagaw & (@as(u8, 1) << @intFromEnum(AddressWidth.bits48))) != 0) return .bits48;
    return null;
}

fn probeUnit(unit: dmar.RemappingUnit, index: usize, host_address_width: u8) Error!UnitRegisters {
    if (unit.segment != 0) return error.FirmwarePolicyUnsupported;
    const register_base = std.math.cast(usize, unit.register_base_address) orelse
        return error.InvalidRegisterRange;
    const virtual_base = KERNEL_VTD_MMIO_VIRTUAL_BASE + index * UNIT_MMIO_STRIDE;
    paging.mapKernelBorrowedPage(
        virtual_base,
        register_base,
        paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE,
    );

    const version = read32(virtual_base + REG_VERSION);
    const major: u8 = @intCast((version >> 4) & 0xF);
    // Major version 6 removes register-based invalidation. The first supported
    // target exposes the current legacy interface; a later queued-invalidation
    // backend should be explicit instead of silently changing semantics here.
    if (major == 0 or major >= 6) return error.UnsupportedHardwareVersion;

    const capability = read64(virtual_base + REG_CAPABILITY);
    const extended = read64(virtual_base + REG_EXTENDED_CAPABILITY);
    try validateCapabilities(capability, extended, host_address_width);

    var iotlb_virtual: usize = 0;
    const enhanced_srtp = (capability & CAP_ENHANCED_SRTP) != 0;
    if (!enhanced_srtp) {
        const invalidate_address_offset =
            ((extended >> ECAP_IOTLB_REGISTER_OFFSET_SHIFT) & ECAP_IOTLB_REGISTER_OFFSET_MASK) * 16;
        const iotlb_offset = invalidate_address_offset + 8;
        if (iotlb_offset + @sizeOf(u64) > unit.registerBytes()) return error.InvalidRegisterRange;
        const iotlb_physical = std.math.add(u64, unit.register_base_address, iotlb_offset) catch
            return error.InvalidRegisterRange;
        const iotlb_page = std.math.cast(usize, iotlb_physical & ~PAGE_MASK) orelse
            return error.InvalidRegisterRange;
        if (iotlb_page == register_base) {
            iotlb_virtual = virtual_base + @as(usize, @intCast(iotlb_offset));
        } else {
            paging.mapKernelBorrowedPage(
                virtual_base + UNIT_IOTLB_PAGE_OFFSET,
                iotlb_page,
                paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE,
            );
            iotlb_virtual = virtual_base + UNIT_IOTLB_PAGE_OFFSET +
                @as(usize, @intCast(iotlb_physical & PAGE_MASK));
        }
    }
    const fault_record_count: u16 = @intCast(
        ((capability >> CAP_FAULT_RECORD_COUNT_SHIFT) & CAP_FAULT_RECORD_COUNT_MASK) + 1,
    );
    const fault_record_offset =
        ((capability >> CAP_FAULT_RECORD_OFFSET_SHIFT) & CAP_FAULT_RECORD_OFFSET_MASK) * 16;
    const fault_record_bytes = @as(u64, fault_record_count) * 16;
    if (fault_record_offset + fault_record_bytes > unit.registerBytes()) {
        return error.InvalidFaultRecordRange;
    }
    const fault_physical = std.math.add(u64, unit.register_base_address, fault_record_offset) catch
        return error.InvalidFaultRecordRange;
    const fault_first_page = fault_physical & ~PAGE_MASK;
    const fault_last_byte = std.math.add(u64, fault_physical, fault_record_bytes - 1) catch
        return error.InvalidFaultRecordRange;
    const fault_page_count = ((fault_last_byte & ~PAGE_MASK) - fault_first_page) / PAGE_SIZE + 1;
    if (fault_page_count > MAX_FAULT_RECORD_PAGES) return error.InvalidFaultRecordRange;
    for (0..@as(usize, @intCast(fault_page_count))) |page_index| {
        paging.mapKernelBorrowedPage(
            virtual_base + UNIT_FAULT_PAGE_OFFSET + page_index * PAGE_SIZE,
            std.math.cast(usize, fault_first_page + page_index * PAGE_SIZE) orelse
                return error.InvalidFaultRecordRange,
            paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE,
        );
    }

    return .{
        .index = @intCast(index),
        .base = virtual_base,
        .iotlb = iotlb_virtual,
        .fault_records = virtual_base + UNIT_FAULT_PAGE_OFFSET +
            @as(usize, @intCast(fault_physical & PAGE_MASK)),
        .fault_record_count = fault_record_count,
        .capability = capability,
        .enhanced_srtp = enhanced_srtp,
        .enhanced_sirtp = (capability & CAP_ENHANCED_SIRTP) != 0,
    };
}

fn validateCapabilities(capability: u64, extended: u64, host_address_width: u8) Error!void {
    if ((extended & ECAP_PAGE_WALK_COHERENT) == 0) return error.NonCoherentPageWalk;
    const remapping = ECAP_QUEUED_INVALIDATION | ECAP_INTERRUPT_REMAP;
    if ((extended & remapping) != remapping) {
        return error.InterruptRemappingUnsupported;
    }
    if ((extended & ECAP_EXTENDED_INTERRUPT_MODE) == 0) {
        return error.ExtendedInterruptModeUnsupported;
    }
    const maximum_guest_width: u8 = @intCast(((capability >> CAP_MGAW_SHIFT) & CAP_MGAW_MASK) + 1);
    if (maximum_guest_width < host_address_width) return error.UnsupportedAddressWidth;
}

const TableBuilder = struct {
    tables: *Tables,
    table_base: u32,
    address_width: AddressWidth,
    next_page: u32 = FIRST_DYNAMIC_TABLE_PAGE,
    context_pages: [256]u8 = [_]u8{0} ** 256,

    fn allocatePage(self: *TableBuilder) Error!u32 {
        if (self.next_page >= TABLE_PAGE_COUNT) return error.TableAllocationFailed;
        const page = self.next_page;
        self.next_page += 1;
        return page;
    }

    fn contextPage(self: *TableBuilder, bus: u8) Error!u32 {
        const slot = &self.context_pages[bus];
        if (slot.* != 0) return slot.*;
        const page = try self.allocatePage();
        slot.* = @intCast(page);
        const root_index = @as(usize, bus) * 2;
        self.tables.*[ROOT_PAGE][root_index] = tablePagePhysical(self.table_base, page) | PRESENT;
        return page;
    }

    fn addDomain(self: *TableBuilder, domain: DmaDomain, domain_id: u16) Error!void {
        const context_page = try self.contextPage(domain.device.bus);
        const l4_page = if (self.address_width == .bits48) try self.allocatePage() else null;
        const l3_page = try self.allocatePage();
        const l2_page = try self.allocatePage();

        const context_index = (@as(usize, domain.device.device) * 8 + domain.device.function) * 2;
        const second_stage_root = tablePagePhysical(
            self.table_base,
            if (l4_page) |page| page else l3_page,
        );
        self.tables.*[context_page][context_index] = second_stage_root | PRESENT;
        self.tables.*[context_page][context_index + 1] = (@as(u64, domain_id) << 8) |
            @intFromEnum(self.address_width);

        if (l4_page) |page| {
            self.tables.*[page][0] = tablePagePhysical(self.table_base, l3_page) |
                SECOND_STAGE_READ | SECOND_STAGE_WRITE;
        }
        self.tables.*[l3_page][0] = tablePagePhysical(self.table_base, l2_page) |
            SECOND_STAGE_READ | SECOND_STAGE_WRITE;

        for (domain.windows) |window| {
            var page_base: u64 = window.base;
            const window_end = @as(u64, window.base) + window.length;
            while (page_base < window_end) : (page_base += PAGE_SIZE) {
                try self.mapPage(l2_page, @intCast(page_base), window);
            }
        }
    }

    fn mapPage(self: *TableBuilder, l2_page: u32, page_base: u32, window: DmaWindow) Error!void {
        const l2_index: usize = @intCast((page_base >> 21) & 0x1FF);
        const l2_entry = &self.tables.*[l2_page][l2_index];
        var leaf_page: u32 = undefined;
        if (l2_entry.* == 0) {
            leaf_page = try self.allocatePage();
            l2_entry.* = tablePagePhysical(self.table_base, leaf_page) |
                SECOND_STAGE_READ | SECOND_STAGE_WRITE;
        } else {
            const leaf_phys = l2_entry.* & ADDRESS_MASK;
            leaf_page = @intCast((leaf_phys - self.table_base) / PAGE_SIZE);
        }

        const leaf_index: usize = @intCast((page_base >> 12) & 0x1FF);
        const leaf_entry = &self.tables.*[leaf_page][leaf_index];
        if (leaf_entry.* != 0) return error.InvalidDmaWindow;
        var permissions: u64 = 0;
        if (window.device_readable) permissions |= SECOND_STAGE_READ;
        if (window.device_writable) permissions |= SECOND_STAGE_WRITE;
        leaf_entry.* = @as(u64, page_base) | permissions;
    }
};

fn populateTables(
    tables: *Tables,
    table_base: u32,
    domains: []const DmaDomain,
    address_width: AddressWidth,
) Error!void {
    @memset(std.mem.asBytes(tables), 0);
    var builder = TableBuilder{
        .tables = tables,
        .table_base = table_base,
        .address_width = address_width,
    };
    for (domains, 0..) |domain, index| {
        try builder.addDomain(domain, FIRST_DOMAIN_ID + @as(u16, @intCast(index)));
    }
}

fn programUnit(unit: UnitRegisters, root_table_base: u32) Error!void {
    var status = read32(unit.base + REG_GLOBAL_STATUS);
    if ((status & (GLOBAL_QUEUED_INVALIDATION_ENABLE | GLOBAL_INTERRUPT_REMAP_ENABLE)) != 0) {
        return error.FirmwareRemappingActive;
    }
    if ((status & GLOBAL_TRANSLATION_ENABLE) != 0) {
        writeGlobalCommand(unit.base, 0, GLOBAL_TRANSLATION_ENABLE);
        try waitForStatus(unit.base, GLOBAL_TRANSLATION_ENABLE, false);
    }

    write64(unit.base + REG_ROOT_TABLE_ADDRESS, root_table_base);
    publishTables();
    writeGlobalCommand(unit.base, GLOBAL_SET_ROOT_TABLE_POINTER, 0);
    try waitForStatus(unit.base, GLOBAL_SET_ROOT_TABLE_POINTER, true);

    if (!unit.enhanced_srtp) {
        write64(
            unit.base + REG_CONTEXT_COMMAND,
            CONTEXT_INVALIDATE | CONTEXT_GLOBAL_INVALIDATION,
        );
        try waitForCommand(unit.base + REG_CONTEXT_COMMAND, CONTEXT_INVALIDATE);
        if ((read64(unit.base + REG_CONTEXT_COMMAND) & CONTEXT_ACTUAL_GRANULARITY_MASK) == 0) {
            return error.CommandRejected;
        }

        write64(unit.iotlb, IOTLB_INVALIDATE | IOTLB_GLOBAL_INVALIDATION);
        try waitForCommand(unit.iotlb, IOTLB_INVALIDATE);
        if ((read64(unit.iotlb) & IOTLB_ACTUAL_GRANULARITY_MASK) == 0) {
            return error.CommandRejected;
        }
    }

    status = read32(unit.base + REG_GLOBAL_STATUS);
    if ((status & GLOBAL_TRANSLATION_ENABLE) == 0) {
        writeGlobalCommand(unit.base, GLOBAL_TRANSLATION_ENABLE, 0);
        try waitForStatus(unit.base, GLOBAL_TRANSLATION_ENABLE, true);
    }
}

fn armFaultMonitoring(unit: UnitRegisters) Error!void {
    // Fault-event interrupts are intentionally masked: the early kernel has no
    // external interrupt dependency and polls the mandatory primary records.
    const fault_control =
        read32(unit.base + REG_FAULT_EVENT_CONTROL) | FAULT_EVENT_INTERRUPT_MASK;
    write32(unit.base + REG_FAULT_EVENT_CONTROL, fault_control);
    if ((read32(unit.base + REG_FAULT_EVENT_CONTROL) & FAULT_EVENT_INTERRUPT_MASK) == 0) {
        return error.CommandRejected;
    }

    for (0..unit.fault_record_count) |index| {
        const record = unit.fault_records + index * 16;
        if ((read64(record + 8) & FAULT_RECORD_PRESENT) != 0) {
            write64(record + 8, FAULT_RECORD_PRESENT);
        }
    }
    var status = read32(unit.base + REG_FAULT_STATUS);
    const clearable = status & (FAULT_STATUS_INVALIDATION_ERRORS | FAULT_STATUS_PRIMARY_OVERFLOW);
    if (clearable != 0) write32(unit.base + REG_FAULT_STATUS, clearable);
    status = read32(unit.base + REG_FAULT_STATUS);
    if ((status & (FAULT_STATUS_PRIMARY_PENDING | FAULT_STATUS_PRIMARY_OVERFLOW |
        FAULT_STATUS_INVALIDATION_ERRORS)) != 0)
    {
        return error.CommandRejected;
    }
}

fn programInterruptRemapping(
    unit: UnitRegisters,
    interrupt_table_base: u64,
    invalidation_queue_base: u64,
) Error!void {
    const interrupt_table_address = interruptTableAddress(interrupt_table_base);
    write64(unit.base + REG_INTERRUPT_REMAP_TABLE_ADDRESS, interrupt_table_address);
    publishTables();
    writeGlobalCommand(unit.base, GLOBAL_SET_INTERRUPT_REMAP_TABLE_POINTER, 0);
    try waitForStatus(unit.base, GLOBAL_SET_INTERRUPT_REMAP_TABLE_POINTER, true);
    if ((read64(unit.base + REG_INTERRUPT_REMAP_TABLE_ADDRESS) &
        (ADDRESS_MASK | INTERRUPT_REMAP_EXTENDED_MODE_ENABLE)) != interrupt_table_address)
    {
        return error.CommandRejected;
    }

    if (!unit.enhanced_sirtp) {
        try globallyInvalidateInterruptEntries(unit, invalidation_queue_base);
    }

    // x2APIC extended mode blocks compatibility-format interrupts. The all-zero
    // IRTE table blocks every remappable interrupt as not-present.
    writeGlobalCommand(
        unit.base,
        GLOBAL_INTERRUPT_REMAP_ENABLE,
        GLOBAL_COMPATIBILITY_FORMAT_INTERRUPT,
    );
    try waitForStatus(unit.base, GLOBAL_INTERRUPT_REMAP_ENABLE, true);
}

fn interruptTableAddress(table_base: u64) u64 {
    return table_base | INTERRUPT_REMAP_EXTENDED_MODE_ENABLE;
}

fn globallyInvalidateInterruptEntries(unit: UnitRegisters, queue_base: u64) Error!void {
    const queue: [*]u64 = @ptrFromInt(queue_base);
    const status_address = queue_base + INVALIDATION_STATUS_OFFSET;
    const completion: *volatile u32 = @ptrFromInt(status_address);

    @memset(@as([*]u8, @ptrFromInt(queue_base))[0..PAGE_SIZE], 0);
    completion.* = 0;
    write64(unit.base + REG_INVALIDATION_QUEUE_TAIL, 0);
    write64(unit.base + REG_INVALIDATION_QUEUE_ADDRESS, queue_base);
    writeGlobalCommand(unit.base, GLOBAL_QUEUED_INVALIDATION_ENABLE, 0);
    try waitForStatus(unit.base, GLOBAL_QUEUED_INVALIDATION_ENABLE, true);

    const descriptors = invalidationDescriptors(status_address);
    queue[0] = descriptors[0][0];
    queue[1] = descriptors[0][1];
    queue[2] = descriptors[1][0];
    queue[3] = descriptors[1][1];
    publishTables();
    write64(unit.base + REG_INVALIDATION_QUEUE_TAIL, INVALIDATION_QUEUE_TAIL);

    var spins: u64 = 0;
    while (spins < COMMAND_SPIN_LIMIT) : (spins += 1) {
        if ((read32(unit.base + REG_FAULT_STATUS) & FAULT_STATUS_INVALIDATION_ERRORS) != 0) {
            return error.InvalidationQueueError;
        }
        if (completion.* == INVALIDATION_STATUS_VALUE and
            read64(unit.base + REG_INVALIDATION_QUEUE_HEAD) == INVALIDATION_QUEUE_TAIL)
        {
            break;
        }
        spinHint();
    } else return error.CommandTimeout;

    writeGlobalCommand(unit.base, 0, GLOBAL_QUEUED_INVALIDATION_ENABLE);
    try waitForStatus(unit.base, GLOBAL_QUEUED_INVALIDATION_ENABLE, false);
}

fn invalidationDescriptors(status_address: u64) [2][2]u64 {
    return .{
        // Type 4, granularity 0: global interrupt-entry-cache invalidation.
        .{ 0x4, 0 },
        // Type 5 with status-write: completion follows the IEC invalidation.
        .{
            (@as(u64, INVALIDATION_STATUS_VALUE) << 32) | (1 << 5) | 0x5,
            status_address,
        },
    };
}

pub fn waitForBlockedWrite(expected_address: u32) Error!FaultRecord {
    if (!faultMonitoringEnabled()) return error.DmaFaultMissing;
    const expected_requester = protectedRequesterId() orelse return error.DmaFaultMissing;
    var spins: u64 = 0;
    while (spins < COMMAND_SPIN_LIMIT) : (spins += 1) {
        if (try pollFault()) |fault| {
            if (!fault.provesBlockedWrite(expected_requester, expected_address)) {
                return error.UnexpectedDmaFault;
            }
            blocked_dma_proof = fault;
            return fault;
        }
        spinHint();
    }
    return error.DmaFaultMissing;
}

fn takeFault() Error!?FaultRecord {
    for (active_units[0..active_unit_count]) |unit| {
        const status = read32(unit.base + REG_FAULT_STATUS);
        if ((status & FAULT_STATUS_PRIMARY_PENDING) == 0) continue;
        const first: u16 = @intCast((status >> FAULT_STATUS_INDEX_SHIFT) & FAULT_STATUS_INDEX_MASK);
        for (0..unit.fault_record_count) |offset| {
            const index = (first + @as(u16, @intCast(offset))) % unit.fault_record_count;
            const address = unit.fault_records + @as(usize, index) * 16;
            const high = read64(address + 8);
            if ((high & FAULT_RECORD_PRESENT) == 0) continue;
            const low = read64(address);
            const record = parseFaultRecord(unit.index, low, high);
            write64(address + 8, FAULT_RECORD_PRESENT);
            clearFaultOverflowIfDrained(unit);
            return record;
        }
        return error.CommandRejected;
    }
    return null;
}

fn clearFaultOverflowIfDrained(unit: UnitRegisters) void {
    const status = read32(unit.base + REG_FAULT_STATUS);
    if ((status & FAULT_STATUS_PRIMARY_PENDING) == 0 and
        (status & FAULT_STATUS_PRIMARY_OVERFLOW) != 0)
    {
        write32(unit.base + REG_FAULT_STATUS, FAULT_STATUS_PRIMARY_OVERFLOW);
    }
}

fn parseFaultRecord(unit_index: u8, low: u64, high: u64) FaultRecord {
    const t1 = (high >> 62) & 1;
    const t2 = (high >> 28) & 1;
    return .{
        .unit_index = unit_index,
        .source_id = @truncate(high),
        .reason = @truncate(high >> 32),
        .request_type = @enumFromInt((t1 << 1) | t2),
        .info = low & ADDRESS_MASK,
    };
}

fn writeGlobalCommand(base: usize, set_bits: u32, clear_bits: u32) void {
    const status = read32(base + REG_GLOBAL_STATUS);
    const command = ((status & GLOBAL_COMMAND_STATUS_MASK) & ~clear_bits) | set_bits;
    write32(base + REG_GLOBAL_COMMAND, command);
}

fn waitForStatus(base: usize, mask: u32, expected_set: bool) Error!void {
    var spins: u64 = 0;
    while (spins < COMMAND_SPIN_LIMIT) : (spins += 1) {
        const set = (read32(base + REG_GLOBAL_STATUS) & mask) != 0;
        if (set == expected_set) return;
        spinHint();
    }
    return error.CommandTimeout;
}

fn waitForCommand(address: usize, pending_mask: u64) Error!void {
    var spins: u64 = 0;
    while (spins < COMMAND_SPIN_LIMIT) : (spins += 1) {
        if ((read64(address) & pending_mask) == 0) return;
        spinHint();
    }
    return error.CommandTimeout;
}

fn requesterId(device_info: pci.PCIDevice) u16 {
    return (@as(u16, device_info.bus) << 8) |
        (@as(u16, device_info.device) << 3) |
        device_info.function;
}

fn protectedRequesterIndex(source_id: u16) ?usize {
    for (protected_requester_ids[0..protected_requester_count], 0..) |protected, index| {
        if (protected == source_id) return index;
    }
    return null;
}

fn pollFaultForSource(source_id: u16) Error!?FaultRecord {
    const requested_index = protectedRequesterIndex(source_id) orelse
        return error.UnexpectedDmaFault;
    if (deferred_faults[requested_index]) |fault| {
        deferred_faults[requested_index] = null;
        return fault;
    }

    const fault = try takeFault() orelse return null;
    return routeObservedFault(source_id, fault);
}

fn routeObservedFault(source_id: u16, fault: FaultRecord) Error!?FaultRecord {
    if (fault.source_id == source_id) return fault;
    const fault_index = protectedRequesterIndex(fault.source_id) orelse
        return error.UnexpectedDmaFault;
    if (deferred_faults[fault_index] != null) return error.UnexpectedDmaFault;
    deferred_faults[fault_index] = fault;
    return null;
}

fn tablePagePhysical(table_base: u32, page: u32) u64 {
    return @as(u64, table_base) + @as(u64, page) * PAGE_SIZE;
}

fn publishTables() void {
    if (comptime builtin.cpu.arch == .x86_64) {
        asm volatile ("mfence" ::: .{ .memory = true });
    } else {
        asm volatile ("" ::: .{ .memory = true });
    }
}

fn spinHint() void {
    if (comptime builtin.cpu.arch == .x86_64) {
        asm volatile ("pause");
    } else {
        asm volatile ("" ::: .{ .memory = true });
    }
}

fn read32(address: usize) u32 {
    return @as(*volatile u32, @ptrFromInt(address)).*;
}

fn write32(address: usize, value: u32) void {
    @as(*volatile u32, @ptrFromInt(address)).* = value;
}

fn read64(address: usize) u64 {
    return @as(*volatile u64, @ptrFromInt(address)).*;
}

fn write64(address: usize, value: u64) void {
    @as(*volatile u64, @ptrFromInt(address)).* = value;
}

fn syntheticNvme() pci.PCIDevice {
    return .{
        .bus = 3,
        .device = 1,
        .function = 2,
        .vendor_id = 0x8086,
        .device_id = 0xF1A8,
        .class_code = pci.PCI_CLASS_STORAGE_CONTROLLER,
        .subclass = pci.PCI_SUBCLASS_NVM,
        .prog_if = pci.PCI_PROG_IF_NVME,
        .bar0 = 0,
        .bar1 = 0,
        .bar2 = 0,
        .bar3 = 0,
        .bar4 = 0,
        .bar5 = 0,
    };
}

fn syntheticI225() pci.PCIDevice {
    var device_info = syntheticNvme();
    device_info.bus = 4;
    device_info.device = 2;
    device_info.function = 0;
    device_info.device_id = 0x15F2;
    device_info.class_code = 0x02;
    device_info.subclass = 0;
    device_info.prog_if = 0;
    return device_info;
}

fn tablePageIndex(table_base: u32, entry: u64) usize {
    return @intCast(((entry & ADDRESS_MASK) - table_base) / PAGE_SIZE);
}

test "VT-d tables expose only the NVMe requester and exact DMA pages" {
    var tables: Tables align(PAGE_SIZE) = undefined;
    const table_base: u32 = 0x0100_0000;
    const windows = [_]DmaWindow{
        .{ .base = 0x0200_0000, .device_readable = true, .device_writable = false },
        .{ .base = 0x0200_1000, .device_readable = false, .device_writable = true },
        .{ .base = 0x0200_2000, .device_readable = true, .device_writable = true },
    };
    const device_info = syntheticNvme();
    const domains = [_]DmaDomain{.{ .device = device_info, .windows = &windows }};
    try populateTables(&tables, table_base, &domains, .bits39);

    const root_index = @as(usize, device_info.bus) * 2;
    const context_page = tablePageIndex(table_base, tables[ROOT_PAGE][root_index]);
    try std.testing.expect(context_page >= FIRST_DYNAMIC_TABLE_PAGE);
    try std.testing.expectEqual(@as(u64, 0), tables[ROOT_PAGE][0]);

    const context_index = (@as(usize, device_info.device) * 8 + device_info.function) * 2;
    const l3_page = tablePageIndex(table_base, tables[context_page][context_index]);
    try std.testing.expectEqual(
        (@as(u64, FIRST_DOMAIN_ID) << 8) | @intFromEnum(AddressWidth.bits39),
        tables[context_page][context_index + 1],
    );
    try std.testing.expectEqual(@as(u64, 0), tables[context_page][0]);

    const l2_page = tablePageIndex(table_base, tables[l3_page][0]);
    const leaf_page = tablePageIndex(table_base, tables[l2_page][@intCast(windows[0].base >> 21)]);
    const leaf = tables[leaf_page];
    try std.testing.expectEqual(@as(u64, windows[0].base) | SECOND_STAGE_READ, leaf[0]);
    try std.testing.expectEqual(@as(u64, windows[1].base) | SECOND_STAGE_WRITE, leaf[1]);
    try std.testing.expectEqual(
        @as(u64, windows[2].base) | SECOND_STAGE_READ | SECOND_STAGE_WRITE,
        leaf[2],
    );
    try std.testing.expectEqual(@as(u64, 0), leaf[3]);
}

test "VT-d tables allocate a distinct leaf table across a 2 MiB boundary" {
    var tables: Tables align(PAGE_SIZE) = undefined;
    const windows = [_]DmaWindow{
        .{ .base = 0x021F_F000, .device_readable = true, .device_writable = false },
        .{ .base = 0x0220_0000, .device_readable = false, .device_writable = true },
    };
    const table_base: u32 = 0x0100_0000;
    const domains = [_]DmaDomain{.{ .device = syntheticNvme(), .windows = &windows }};
    try populateTables(&tables, table_base, &domains, .bits48);

    const first_l2: usize = @intCast((windows[0].base >> 21) & 0x1FF);
    const second_l2: usize = @intCast((windows[1].base >> 21) & 0x1FF);
    try std.testing.expect(first_l2 != second_l2);
    const root_entry = tables[ROOT_PAGE][@as(usize, syntheticNvme().bus) * 2];
    const context_page = tablePageIndex(table_base, root_entry);
    const context_index = (@as(usize, syntheticNvme().device) * 8 + syntheticNvme().function) * 2;
    const l4_page = tablePageIndex(table_base, tables[context_page][context_index]);
    const l3_page = tablePageIndex(table_base, tables[l4_page][0]);
    const l2_page = tablePageIndex(table_base, tables[l3_page][0]);
    try std.testing.expect(tables[l2_page][first_l2] != 0);
    try std.testing.expect(tables[l2_page][second_l2] != 0);
    try std.testing.expect(tablePageIndex(table_base, tables[l2_page][first_l2]) !=
        tablePageIndex(table_base, tables[l2_page][second_l2]));
}

test "VT-d domains isolate NVMe and I225 requesters with multi-page windows" {
    var tables: Tables align(PAGE_SIZE) = undefined;
    const table_base: u32 = 0x0100_0000;
    const storage_windows = [_]DmaWindow{
        .{ .base = 0x0200_0000, .device_readable = true, .device_writable = true },
    };
    const network_windows = [_]DmaWindow{
        .{ .base = 0x0240_0000, .length = 2 * PAGE_SIZE, .device_readable = true, .device_writable = false },
    };
    const domains = [_]DmaDomain{
        .{ .device = syntheticNvme(), .windows = &storage_windows },
        .{ .device = syntheticI225(), .windows = &network_windows },
    };
    try validateDomains(&domains);
    try populateTables(&tables, table_base, &domains, .bits39);

    const nvme_context_page = tablePageIndex(
        table_base,
        tables[ROOT_PAGE][@as(usize, syntheticNvme().bus) * 2],
    );
    const i225_context_page = tablePageIndex(
        table_base,
        tables[ROOT_PAGE][@as(usize, syntheticI225().bus) * 2],
    );
    try std.testing.expect(nvme_context_page != i225_context_page);

    const nvme_context_index = (@as(usize, syntheticNvme().device) * 8 + syntheticNvme().function) * 2;
    const i225_context_index = (@as(usize, syntheticI225().device) * 8 + syntheticI225().function) * 2;
    try std.testing.expectEqual(
        (@as(u64, FIRST_DOMAIN_ID) << 8) | @intFromEnum(AddressWidth.bits39),
        tables[nvme_context_page][nvme_context_index + 1],
    );
    try std.testing.expectEqual(
        (@as(u64, FIRST_DOMAIN_ID + 1) << 8) | @intFromEnum(AddressWidth.bits39),
        tables[i225_context_page][i225_context_index + 1],
    );

    const i225_l3 = tablePageIndex(table_base, tables[i225_context_page][i225_context_index]);
    const i225_l2 = tablePageIndex(table_base, tables[i225_l3][0]);
    const i225_leaf = tablePageIndex(
        table_base,
        tables[i225_l2][@intCast(network_windows[0].base >> 21)],
    );
    const first_leaf_index: usize = @intCast(network_windows[0].base >> 12 & 0x1FF);
    try std.testing.expectEqual(
        @as(u64, network_windows[0].base) | SECOND_STAGE_READ,
        tables[i225_leaf][first_leaf_index],
    );
    try std.testing.expectEqual(
        @as(u64, network_windows[0].base + PAGE_SIZE) | SECOND_STAGE_READ,
        tables[i225_leaf][first_leaf_index + 1],
    );
}

test "VT-d window policy rejects aliases and capability selection prefers fewer walks" {
    const aliased = [_]DmaWindow{
        .{ .base = 0x0200_0000, .device_readable = true, .device_writable = false },
        .{ .base = 0x0200_0000, .device_readable = false, .device_writable = true },
    };
    try std.testing.expectError(error.InvalidDmaWindow, validateWindows(&aliased));
    const storage_windows = [_]DmaWindow{
        .{ .base = 0x0200_0000, .length = 2 * PAGE_SIZE, .device_readable = true, .device_writable = true },
    };
    const overlapping_network_windows = [_]DmaWindow{
        .{ .base = 0x0200_1000, .device_readable = true, .device_writable = false },
    };
    const overlapping_domains = [_]DmaDomain{
        .{ .device = syntheticNvme(), .windows = &storage_windows },
        .{ .device = syntheticI225(), .windows = &overlapping_network_windows },
    };
    try std.testing.expectError(error.InvalidDmaWindow, validateDomains(&overlapping_domains));
    try std.testing.expectEqual(AddressWidth.bits39, chooseAddressWidth(0b00110).?);
    try std.testing.expectEqual(AddressWidth.bits48, chooseAddressWidth(0b00100).?);
    try std.testing.expect(chooseAddressWidth(0b00001) == null);
}

test "VT-d fault routing retains a record for the owning requester" {
    protected_requester_ids = .{ requesterId(syntheticNvme()), requesterId(syntheticI225()) };
    protected_requester_count = 2;
    deferred_faults = [_]?FaultRecord{null} ** MAX_DMA_DOMAINS;
    defer {
        protected_requester_ids = [_]u16{0} ** MAX_DMA_DOMAINS;
        protected_requester_count = 0;
        deferred_faults = [_]?FaultRecord{null} ** MAX_DMA_DOMAINS;
    }
    const network_fault = FaultRecord{
        .unit_index = 0,
        .source_id = requesterId(syntheticI225()),
        .reason = 1,
        .request_type = .read,
        .info = 0x0240_0000,
    };
    try std.testing.expect((try routeObservedFault(requesterId(syntheticNvme()), network_fault)) == null);
    const routed = (try pollFaultForSource(requesterId(syntheticI225()))).?;
    try std.testing.expectEqual(network_fault, routed);
}

test "VT-d interrupt table denies every interrupt and invalidation is completion fenced" {
    var table: InterruptTable align(PAGE_SIZE) = undefined;
    @memset(std.mem.asBytes(&table), 0);
    for (table) |entry| {
        try std.testing.expectEqual(@as(u64, 0), entry[0]);
        try std.testing.expectEqual(@as(u64, 0), entry[1]);
    }

    const status_address: u64 = 0x0200_0FFC;
    try std.testing.expectEqual(
        @as(u64, 0x0200_0800),
        interruptTableAddress(0x0200_0000),
    );
    const descriptors = invalidationDescriptors(status_address);
    try std.testing.expectEqual(@as(u64, 0x4), descriptors[0][0]);
    try std.testing.expectEqual(@as(u64, 0), descriptors[0][1]);
    try std.testing.expectEqual(
        (@as(u64, INVALIDATION_STATUS_VALUE) << 32) | (1 << 5) | 0x5,
        descriptors[1][0],
    );
    try std.testing.expectEqual(status_address, descriptors[1][1]);
}

test "VT-d primary fault parser binds requester address and write direction" {
    const requester: u16 = 0x031A;
    const reason: u8 = 0x05;
    const address: u64 = 0x0234_5000;
    const high = FAULT_RECORD_PRESENT |
        (@as(u64, reason) << 32) |
        requester;
    const fault = parseFaultRecord(2, address, high);
    try std.testing.expectEqual(@as(u8, 2), fault.unit_index);
    try std.testing.expectEqual(requester, fault.source_id);
    try std.testing.expectEqual(reason, fault.reason);
    try std.testing.expectEqual(RequestType.write, fault.request_type);
    try std.testing.expectEqual(address, fault.info);
    try std.testing.expect(fault.provesBlockedWrite(requester, @truncate(address)));

    var wrong_source = fault;
    wrong_source.source_id +%= 1;
    try std.testing.expect(!wrong_source.provesBlockedWrite(requester, @truncate(address)));
    var interrupt_fault = fault;
    interrupt_fault.reason = 0x22;
    try std.testing.expect(!interrupt_fault.provesBlockedWrite(requester, @truncate(address)));
    var read_fault = fault;
    read_fault.request_type = .read;
    try std.testing.expect(!read_fault.provesBlockedWrite(requester, @truncate(address)));
}

test "VT-d interrupt isolation requires coherent queued-remapping hardware" {
    const capability = @as(u64, 47) << CAP_MGAW_SHIFT;
    const required = ECAP_PAGE_WALK_COHERENT |
        ECAP_QUEUED_INVALIDATION |
        ECAP_INTERRUPT_REMAP |
        ECAP_EXTENDED_INTERRUPT_MODE;
    try validateCapabilities(capability, required, 39);
    try std.testing.expectError(
        error.NonCoherentPageWalk,
        validateCapabilities(capability, required & ~ECAP_PAGE_WALK_COHERENT, 39),
    );
    try std.testing.expectError(
        error.InterruptRemappingUnsupported,
        validateCapabilities(capability, required & ~ECAP_INTERRUPT_REMAP, 39),
    );
    try std.testing.expectError(
        error.ExtendedInterruptModeUnsupported,
        validateCapabilities(capability, required & ~ECAP_EXTENDED_INTERRUPT_MODE, 39),
    );
    try std.testing.expectError(
        error.UnsupportedAddressWidth,
        validateCapabilities(@as(u64, 37) << CAP_MGAW_SHIFT, required, 39),
    );
}
