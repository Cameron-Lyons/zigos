const std = @import("std");
const acpi = @import("acpi.zig");
const checksum = @import("../utils/checksum.zig");
const endian = @import("../utils/endian.zig");

pub const DMAR_SIGNATURE = "DMAR";
pub const DMAR_HEADER_LENGTH: usize = acpi.SDT_HEADER_LENGTH + 12;
pub const MAX_REMAPPING_UNITS: usize = 16;
pub const MIN_PRODUCTION_HOST_ADDRESS_WIDTH: u8 = 39;
pub const COMPACT_SUMMARY_COUNT_METADATA = true;
pub const SUMMARY_SIZE_CEILING_BYTES: usize = 408;

const HOST_ADDRESS_WIDTH_OFFSET: usize = acpi.SDT_HEADER_LENGTH;
const FLAGS_OFFSET: usize = HOST_ADDRESS_WIDTH_OFFSET + 1;
const RESERVED_OFFSET: usize = FLAGS_OFFSET + 1;
const RESERVED_BYTES: usize = 10;
const REMAPPING_STRUCTURE_HEADER_BYTES: usize = 4;
const REMAPPING_STRUCTURE_TYPE_OFFSET: usize = 0;
const REMAPPING_STRUCTURE_LENGTH_OFFSET: usize = 2;

const FLAG_INTERRUPT_REMAPPING: u8 = 1 << 0;
const FLAG_X2APIC_OPT_OUT: u8 = 1 << 1;
const FLAG_DMA_CONTROL_PLATFORM_OPT_IN: u8 = 1 << 2;
const FLAG_DMA_REMAPPING_OPT_OUT: u8 = 1 << 3;
const VALID_DMAR_FLAGS: u8 = FLAG_INTERRUPT_REMAPPING |
    FLAG_X2APIC_OPT_OUT |
    FLAG_DMA_CONTROL_PLATFORM_OPT_IN |
    FLAG_DMA_REMAPPING_OPT_OUT;

const DRHD_TYPE: u16 = 0;
const RMRR_TYPE: u16 = 1;
const ATSR_TYPE: u16 = 2;
const DRHD_MIN_BYTES: usize = 16;
const RMRR_MIN_BYTES: usize = 24;
const ATSR_MIN_BYTES: usize = 8;
const DRHD_FLAG_INCLUDE_PCI_ALL: u8 = 1 << 0;
const ATSR_FLAG_ALL_PORTS: u8 = 1 << 0;
const PAGE_SIZE: u64 = 4096;

comptime {
    if (MAX_REMAPPING_UNITS > std.math.maxInt(u8)) {
        @compileError("DMAR remapping units no longer fit compact summary metadata");
    }
}

const DEVICE_SCOPE_HEADER_BYTES: usize = 6;
const DEVICE_SCOPE_MIN_BYTES: usize = DEVICE_SCOPE_HEADER_BYTES + 2;
const DEVICE_SCOPE_FLAGS_OFFSET: usize = 2;
const DEVICE_SCOPE_RESERVED_OFFSET: usize = 3;
const DEVICE_SCOPE_TYPE_PCI_ENDPOINT: u8 = 1;
const DEVICE_SCOPE_TYPE_PCI_SUB_HIERARCHY: u8 = 2;
const DEVICE_SCOPE_TYPE_IO_APIC: u8 = 3;
const DEVICE_SCOPE_TYPE_MSI_HPET: u8 = 4;
const DEVICE_SCOPE_TYPE_ACPI_NAMESPACE: u8 = 5;

pub const Error = error{
    TooSmall,
    BadSignature,
    BadChecksum,
    UnsupportedRevision,
    InvalidLength,
    InvalidFlags,
    InvalidReserved,
    InvalidHostAddressWidth,
    InvalidStructureOrder,
    InvalidRemappingUnit,
    InvalidReservedMemoryRegion,
    InvalidAtsCapability,
    InvalidDeviceScope,
    MissingRemappingUnit,
    TooManyRemappingUnits,
};

pub const RemappingUnit = struct {
    register_base_address: u64 = 0,
    register_page_count: u32 = 0,
    segment: u16 = 0,
    include_pci_all: bool = false,
    device_scope_count: u16 = 0,

    pub fn registerBytes(self: RemappingUnit) u64 {
        return @as(u64, self.register_page_count) * PAGE_SIZE;
    }
};

pub const Summary = struct {
    host_address_width: u8,
    interrupt_remapping: bool,
    x2apic_opt_out: bool,
    dma_control_platform_opt_in: bool,
    dma_remapping_opt_out: bool,
    remapping_units: [MAX_REMAPPING_UNITS]RemappingUnit =
        [_]RemappingUnit{.{}} ** MAX_REMAPPING_UNITS,
    remapping_unit_count: u8 = 0,
    reserved_memory_region_count: u32 = 0,
    reserved_memory_with_non_pci_scope_count: u32 = 0,
    ats_capability_count: u32 = 0,

    pub fn units(self: *const Summary) []const RemappingUnit {
        return self.remapping_units[0..@as(usize, self.remapping_unit_count)];
    }

    pub fn segmentZeroCatchAll(self: *const Summary) ?*const RemappingUnit {
        for (self.units()) |*unit| {
            if (unit.segment == 0 and unit.include_pci_all) return unit;
        }
        return null;
    }

    pub fn coversSegment(self: *const Summary, segment: u16) bool {
        for (self.units()) |unit| {
            if (unit.segment == segment) return true;
        }
        return false;
    }

    pub fn productionDiscoveryReady(self: *const Summary) bool {
        return self.host_address_width >= MIN_PRODUCTION_HOST_ADDRESS_WIDTH and
            self.interrupt_remapping and
            !self.x2apic_opt_out and
            !self.dma_remapping_opt_out and
            self.segmentZeroCatchAll() != null;
    }

    pub fn productionEnforcementReady(self: *const Summary) bool {
        if (!self.productionDiscoveryReady() or self.reserved_memory_with_non_pci_scope_count != 0) {
            return false;
        }
        for (self.units()) |unit| {
            if (unit.segment != 0) return false;
        }
        return true;
    }

    comptime {
        if (@sizeOf(@This()) > SUMMARY_SIZE_CEILING_BYTES) {
            @compileError("DMAR summary exceeds its compact size ceiling");
        }
    }
};

const DeviceScopeSummary = struct {
    count: u16 = 0,
    only_pci_devices: bool = true,
};

const ReservedMemoryRegion = struct {
    segment: u16,
    only_pci_devices: bool,
};

const ScopePolicy = enum {
    any,
    interrupt_sources_only,
    pci_sub_hierarchy_only,
};

pub fn parseDmar(table: []const u8) Error!Summary {
    if (table.len < DMAR_HEADER_LENGTH) return error.TooSmall;
    if (!std.mem.eql(u8, table[0..DMAR_SIGNATURE.len], DMAR_SIGNATURE)) return error.BadSignature;

    const header = try acpi.parseSdtHeader(table);
    if (header.revision != 1) return error.UnsupportedRevision;
    const table_length: usize = @intCast(header.length);
    if (table_length < DMAR_HEADER_LENGTH) return error.InvalidLength;

    const raw_host_address_width = table[HOST_ADDRESS_WIDTH_OFFSET];
    if (raw_host_address_width >= 64) {
        return error.InvalidHostAddressWidth;
    }
    const host_address_width = raw_host_address_width + 1;
    const flags = table[FLAGS_OFFSET];
    if ((flags & ~VALID_DMAR_FLAGS) != 0) return error.InvalidFlags;
    if ((flags & FLAG_X2APIC_OPT_OUT) != 0 and (flags & FLAG_INTERRUPT_REMAPPING) == 0) {
        return error.InvalidFlags;
    }
    if (!allZero(table[RESERVED_OFFSET .. RESERVED_OFFSET + RESERVED_BYTES])) {
        return error.InvalidReserved;
    }

    var summary = Summary{
        .host_address_width = host_address_width,
        .interrupt_remapping = (flags & FLAG_INTERRUPT_REMAPPING) != 0,
        .x2apic_opt_out = (flags & FLAG_X2APIC_OPT_OUT) != 0,
        .dma_control_platform_opt_in = (flags & FLAG_DMA_CONTROL_PLATFORM_OPT_IN) != 0,
        .dma_remapping_opt_out = (flags & FLAG_DMA_REMAPPING_OPT_OUT) != 0,
    };
    var previous_type: ?u16 = null;
    var offset: usize = DMAR_HEADER_LENGTH;
    while (offset < table_length) {
        if (table_length - offset < REMAPPING_STRUCTURE_HEADER_BYTES) return error.InvalidLength;
        const structure_type = endian.readU16Le(
            table[offset + REMAPPING_STRUCTURE_TYPE_OFFSET ..][0..2],
        );
        const structure_length: usize = endian.readU16Le(
            table[offset + REMAPPING_STRUCTURE_LENGTH_OFFSET ..][0..2],
        );
        if (structure_length < REMAPPING_STRUCTURE_HEADER_BYTES or structure_length > table_length - offset) {
            return error.InvalidLength;
        }
        if (previous_type) |prior| {
            if (structure_type < prior) return error.InvalidStructureOrder;
        }
        previous_type = structure_type;

        const structure = table[offset .. offset + structure_length];
        switch (structure_type) {
            DRHD_TYPE => {
                const unit = try parseRemappingUnit(structure, host_address_width);
                const unit_count: usize = summary.remapping_unit_count;
                if (unit_count >= summary.remapping_units.len) {
                    return error.TooManyRemappingUnits;
                }
                for (summary.units()) |prior| {
                    if (prior.segment == unit.segment and prior.include_pci_all) {
                        return error.InvalidStructureOrder;
                    }
                    if (rangesOverlap(
                        prior.register_base_address,
                        prior.registerBytes(),
                        unit.register_base_address,
                        unit.registerBytes(),
                    )) return error.InvalidRemappingUnit;
                }
                summary.remapping_units[unit_count] = unit;
                summary.remapping_unit_count += 1;
            },
            RMRR_TYPE => {
                const region = try validateReservedMemoryRegion(structure, host_address_width);
                if (!summary.coversSegment(region.segment)) return error.InvalidReservedMemoryRegion;
                summary.reserved_memory_region_count += 1;
                if (!region.only_pci_devices) {
                    summary.reserved_memory_with_non_pci_scope_count += 1;
                }
            },
            ATSR_TYPE => {
                const segment = try validateAtsCapability(structure);
                if (!summary.coversSegment(segment)) return error.InvalidAtsCapability;
                summary.ats_capability_count += 1;
            },
            else => {},
        }
        offset += structure_length;
    }
    if (summary.remapping_unit_count == 0) return error.MissingRemappingUnit;
    return summary;
}

fn parseRemappingUnit(structure: []const u8, host_address_width: u8) Error!RemappingUnit {
    if (structure.len < DRHD_MIN_BYTES) return error.InvalidRemappingUnit;
    const flags = structure[4];
    if ((flags & ~DRHD_FLAG_INCLUDE_PCI_ALL) != 0) return error.InvalidFlags;
    const size_exponent = structure[5];
    if ((size_exponent & 0xF0) != 0) return error.InvalidReserved;
    const register_shift: u6 = @intCast(@as(u16, size_exponent) + 12);
    const register_bytes = @as(u64, 1) << register_shift;
    const register_base_address = endian.readU64Le(structure[8..16]);
    if (register_base_address == 0 or register_base_address % register_bytes != 0) {
        return error.InvalidRemappingUnit;
    }
    if (!rangeFitsHostAddressWidth(register_base_address, register_bytes, host_address_width)) {
        return error.InvalidRemappingUnit;
    }

    const include_pci_all = (flags & DRHD_FLAG_INCLUDE_PCI_ALL) != 0;
    const scope_summary = try validateDeviceScopes(
        structure[DRHD_MIN_BYTES..],
        false,
        if (include_pci_all) .interrupt_sources_only else .any,
    );
    return .{
        .register_base_address = register_base_address,
        .register_page_count = @as(u32, 1) << @intCast(size_exponent),
        .segment = endian.readU16Le(structure[6..8]),
        .include_pci_all = include_pci_all,
        .device_scope_count = scope_summary.count,
    };
}

fn validateReservedMemoryRegion(structure: []const u8, host_address_width: u8) Error!ReservedMemoryRegion {
    if (structure.len < RMRR_MIN_BYTES) return error.InvalidReservedMemoryRegion;
    if (endian.readU16Le(structure[4..6]) != 0) return error.InvalidReserved;
    const base = endian.readU64Le(structure[8..16]);
    const limit = endian.readU64Le(structure[16..24]);
    if (base % PAGE_SIZE != 0 or limit <= base) {
        return error.InvalidReservedMemoryRegion;
    }
    const length = std.math.add(u64, limit - base, 1) catch
        return error.InvalidReservedMemoryRegion;
    if (length % PAGE_SIZE != 0 or !rangeFitsHostAddressWidth(base, length, host_address_width)) {
        return error.InvalidReservedMemoryRegion;
    }
    const scopes = try validateDeviceScopes(structure[RMRR_MIN_BYTES..], true, .any);
    return .{
        .segment = endian.readU16Le(structure[6..8]),
        .only_pci_devices = scopes.only_pci_devices,
    };
}

fn validateAtsCapability(structure: []const u8) Error!u16 {
    if (structure.len < ATSR_MIN_BYTES) return error.InvalidAtsCapability;
    const flags = structure[4];
    if ((flags & ~ATSR_FLAG_ALL_PORTS) != 0) return error.InvalidFlags;
    if (structure[5] != 0) return error.InvalidReserved;
    const scopes = structure[ATSR_MIN_BYTES..];
    if ((flags & ATSR_FLAG_ALL_PORTS) != 0) {
        if (scopes.len != 0) return error.InvalidAtsCapability;
        return endian.readU16Le(structure[6..8]);
    }
    _ = try validateDeviceScopes(scopes, true, .pci_sub_hierarchy_only);
    return endian.readU16Le(structure[6..8]);
}

fn validateDeviceScopes(bytes: []const u8, required: bool, policy: ScopePolicy) Error!DeviceScopeSummary {
    var summary = DeviceScopeSummary{};
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (bytes.len - offset < DEVICE_SCOPE_HEADER_BYTES) return error.InvalidDeviceScope;
        const scope_type = bytes[offset];
        const scope_length: usize = bytes[offset + 1];
        if (scope_length < DEVICE_SCOPE_MIN_BYTES or scope_length > bytes.len - offset) {
            return error.InvalidDeviceScope;
        }
        if ((scope_length - DEVICE_SCOPE_HEADER_BYTES) % 2 != 0) return error.InvalidDeviceScope;
        if (scope_type < DEVICE_SCOPE_TYPE_PCI_ENDPOINT or scope_type > DEVICE_SCOPE_TYPE_ACPI_NAMESPACE) {
            return error.InvalidDeviceScope;
        }
        if (bytes[offset + DEVICE_SCOPE_FLAGS_OFFSET] != 0 or
            bytes[offset + DEVICE_SCOPE_RESERVED_OFFSET] != 0)
        {
            return error.InvalidReserved;
        }
        switch (policy) {
            .any => {},
            .interrupt_sources_only => if (scope_type != DEVICE_SCOPE_TYPE_IO_APIC and
                scope_type != DEVICE_SCOPE_TYPE_MSI_HPET)
            {
                return error.InvalidDeviceScope;
            },
            .pci_sub_hierarchy_only => if (scope_type != DEVICE_SCOPE_TYPE_PCI_SUB_HIERARCHY) {
                return error.InvalidDeviceScope;
            },
        }
        if (scope_type != DEVICE_SCOPE_TYPE_PCI_ENDPOINT and
            scope_type != DEVICE_SCOPE_TYPE_PCI_SUB_HIERARCHY)
        {
            summary.only_pci_devices = false;
        }

        var path_offset = offset + DEVICE_SCOPE_HEADER_BYTES;
        const scope_end = offset + scope_length;
        while (path_offset < scope_end) : (path_offset += 2) {
            if (bytes[path_offset] > 31 or bytes[path_offset + 1] > 7) {
                return error.InvalidDeviceScope;
            }
        }
        summary.count = std.math.add(u16, summary.count, 1) catch return error.InvalidDeviceScope;
        offset = scope_end;
    }
    if (required and summary.count == 0) return error.InvalidDeviceScope;
    return summary;
}

fn rangeFitsHostAddressWidth(base: u64, length: u64, host_address_width: u8) bool {
    if (length == 0) return false;
    const last = std.math.add(u64, base, length - 1) catch return false;
    if (host_address_width == 64) return true;
    const shift: u6 = @intCast(host_address_width);
    return last < (@as(u64, 1) << shift);
}

fn rangesOverlap(first_base: u64, first_length: u64, second_base: u64, second_length: u64) bool {
    const first_end = std.math.add(u64, first_base, first_length - 1) catch return true;
    const second_end = std.math.add(u64, second_base, second_length - 1) catch return true;
    return first_base <= second_end and second_base <= first_end;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

const TEST_TABLE_BYTES: usize = 120;

fn validDmar() [TEST_TABLE_BYTES]u8 {
    var table = [_]u8{0} ** TEST_TABLE_BYTES;
    @memcpy(table[0..4], DMAR_SIGNATURE);
    endian.writeU32Le(table[4..8], table.len);
    table[8] = 1;
    @memcpy(table[10..16], "ZIGOS ");
    @memcpy(table[16..24], "NUC11VTD");
    table[HOST_ADDRESS_WIDTH_OFFSET] = MIN_PRODUCTION_HOST_ADDRESS_WIDTH - 1;
    table[FLAGS_OFFSET] = FLAG_INTERRUPT_REMAPPING | FLAG_DMA_CONTROL_PLATFORM_OPT_IN;

    endian.writeU16Le(table[48..50], DRHD_TYPE);
    endian.writeU16Le(table[50..52], 24);
    endian.writeU64Le(table[56..64], 0x0000_0000_FED9_0000);
    table[64] = DEVICE_SCOPE_TYPE_PCI_ENDPOINT;
    table[65] = 8;
    table[70] = 2;
    table[71] = 0;

    endian.writeU16Le(table[72..74], DRHD_TYPE);
    endian.writeU16Le(table[74..76], 16);
    table[76] = DRHD_FLAG_INCLUDE_PCI_ALL;
    endian.writeU64Le(table[80..88], 0x0000_0000_FED9_1000);

    endian.writeU16Le(table[88..90], RMRR_TYPE);
    endian.writeU16Le(table[90..92], 32);
    endian.writeU64Le(table[96..104], 0x0000_0000_7D00_0000);
    endian.writeU64Le(table[104..112], 0x0000_0000_7D00_1FFF);
    table[112] = DEVICE_SCOPE_TYPE_PCI_ENDPOINT;
    table[113] = 8;
    table[118] = 20;
    table[119] = 0;

    checksum.finishSum8Prefix(table[0..], 9, table.len);
    return table;
}

test "DMAR summary uses capacity-sized discovery counts" {
    try std.testing.expect(COMPACT_SUMMARY_COUNT_METADATA);
    try std.testing.expectEqual(u8, @FieldType(Summary, "remapping_unit_count"));
    try std.testing.expectEqual(u32, @FieldType(Summary, "reserved_memory_region_count"));
    try std.testing.expectEqual(u32, @FieldType(Summary, "reserved_memory_with_non_pci_scope_count"));
    try std.testing.expectEqual(u32, @FieldType(Summary, "ats_capability_count"));
    try std.testing.expectEqual(@as(usize, SUMMARY_SIZE_CEILING_BYTES), @sizeOf(Summary));
}

test "DMAR parser discovers production-policy segment-zero VT-d units" {
    const table = validDmar();
    const summary = try parseDmar(table[0..]);
    try std.testing.expectEqual(MIN_PRODUCTION_HOST_ADDRESS_WIDTH, summary.host_address_width);
    try std.testing.expect(summary.interrupt_remapping);
    try std.testing.expect(summary.dma_control_platform_opt_in);
    try std.testing.expect(!summary.x2apic_opt_out);
    try std.testing.expect(!summary.dma_remapping_opt_out);
    try std.testing.expectEqual(@as(usize, 2), summary.units().len);
    try std.testing.expectEqual(@as(u32, 1), summary.reserved_memory_region_count);
    try std.testing.expectEqual(@as(u32, 0), summary.reserved_memory_with_non_pci_scope_count);
    const catch_all = summary.segmentZeroCatchAll().?;
    try std.testing.expectEqual(@as(u64, 0xFED9_1000), catch_all.register_base_address);
    try std.testing.expectEqual(@as(u32, 1), catch_all.register_page_count);
    try std.testing.expect(summary.productionDiscoveryReady());
    try std.testing.expect(summary.productionEnforcementReady());
}

test "DMAR enforcement policy rejects reserved memory owned by non-PCI DMA devices" {
    var table = validDmar();
    table[112] = DEVICE_SCOPE_TYPE_ACPI_NAMESPACE;
    checksum.finishSum8Prefix(table[0..], 9, table.len);

    const summary = try parseDmar(table[0..]);
    try std.testing.expect(summary.productionDiscoveryReady());
    try std.testing.expectEqual(@as(u32, 1), summary.reserved_memory_with_non_pci_scope_count);
    try std.testing.expect(!summary.productionEnforcementReady());
}

test "DMAR enforcement policy rejects units outside the only scanned PCI segment" {
    const table = validDmar();
    var summary = try parseDmar(table[0..]);
    const next_unit_index: usize = summary.remapping_unit_count;
    summary.remapping_units[next_unit_index] = .{
        .register_base_address = 0x0000_0000_FEDA_0000,
        .register_page_count = 1,
        .segment = 1,
        .include_pci_all = true,
    };
    summary.remapping_unit_count += 1;

    try std.testing.expect(summary.productionDiscoveryReady());
    try std.testing.expect(!summary.productionEnforcementReady());
}

test "DMAR parser rejects corrupt headers and reserved fields" {
    var bad_checksum = validDmar();
    bad_checksum[80] +%= 1;
    try std.testing.expectError(error.BadChecksum, parseDmar(bad_checksum[0..]));

    var bad_revision = validDmar();
    bad_revision[8] = 2;
    checksum.finishSum8Prefix(bad_revision[0..], 9, bad_revision.len);
    try std.testing.expectError(error.UnsupportedRevision, parseDmar(bad_revision[0..]));

    var reserved_flag = validDmar();
    reserved_flag[FLAGS_OFFSET] |= 1 << 7;
    checksum.finishSum8Prefix(reserved_flag[0..], 9, reserved_flag.len);
    try std.testing.expectError(error.InvalidFlags, parseDmar(reserved_flag[0..]));

    var reserved_byte = validDmar();
    reserved_byte[RESERVED_OFFSET] = 1;
    checksum.finishSum8Prefix(reserved_byte[0..], 9, reserved_byte.len);
    try std.testing.expectError(error.InvalidReserved, parseDmar(reserved_byte[0..]));
}

test "DMAR production policy rejects firmware opt-outs and narrow DMA addresses" {
    var opt_out = validDmar();
    opt_out[FLAGS_OFFSET] |= FLAG_X2APIC_OPT_OUT | FLAG_DMA_REMAPPING_OPT_OUT;
    checksum.finishSum8Prefix(opt_out[0..], 9, opt_out.len);
    const opt_out_summary = try parseDmar(opt_out[0..]);
    try std.testing.expect(!opt_out_summary.productionDiscoveryReady());

    var narrow = validDmar();
    narrow[HOST_ADDRESS_WIDTH_OFFSET] = MIN_PRODUCTION_HOST_ADDRESS_WIDTH - 2;
    checksum.finishSum8Prefix(narrow[0..], 9, narrow.len);
    const narrow_summary = try parseDmar(narrow[0..]);
    try std.testing.expect(!narrow_summary.productionDiscoveryReady());
}

test "DMAR parser validates register sizing order and segment-zero coverage" {
    var bad_alignment = validDmar();
    bad_alignment[77] = 1;
    checksum.finishSum8Prefix(bad_alignment[0..], 9, bad_alignment.len);
    try std.testing.expectError(error.InvalidRemappingUnit, parseDmar(bad_alignment[0..]));

    var after_catch_all = validDmar();
    endian.writeU32Le(after_catch_all[4..8], 104);
    endian.writeU16Le(after_catch_all[88..90], DRHD_TYPE);
    endian.writeU16Le(after_catch_all[90..92], DRHD_MIN_BYTES);
    endian.writeU64Le(after_catch_all[96..104], 0x0000_0000_FED9_2000);
    checksum.finishSum8Prefix(after_catch_all[0..], 9, 104);
    try std.testing.expectError(error.InvalidStructureOrder, parseDmar(after_catch_all[0..]));

    var no_catch_all = validDmar();
    no_catch_all[76] = 0;
    checksum.finishSum8Prefix(no_catch_all[0..], 9, no_catch_all.len);
    const summary = try parseDmar(no_catch_all[0..]);
    try std.testing.expect(summary.segmentZeroCatchAll() == null);
    try std.testing.expect(!summary.productionDiscoveryReady());

    var out_of_order = validDmar();
    endian.writeU16Le(out_of_order[48..50], 7);
    checksum.finishSum8Prefix(out_of_order[0..], 9, out_of_order.len);
    try std.testing.expectError(error.InvalidStructureOrder, parseDmar(out_of_order[0..]));
}

test "DMAR parser rejects malformed device scopes and reserved memory regions" {
    var bad_scope_length = validDmar();
    bad_scope_length[65] = 7;
    checksum.finishSum8Prefix(bad_scope_length[0..], 9, bad_scope_length.len);
    try std.testing.expectError(error.InvalidDeviceScope, parseDmar(bad_scope_length[0..]));

    var bad_scope_path = validDmar();
    bad_scope_path[70] = 32;
    checksum.finishSum8Prefix(bad_scope_path[0..], 9, bad_scope_path.len);
    try std.testing.expectError(error.InvalidDeviceScope, parseDmar(bad_scope_path[0..]));

    var bad_scope_flags = validDmar();
    bad_scope_flags[66] = 1;
    checksum.finishSum8Prefix(bad_scope_flags[0..], 9, bad_scope_flags.len);
    try std.testing.expectError(error.InvalidReserved, parseDmar(bad_scope_flags[0..]));

    var bad_reserved_region = validDmar();
    endian.writeU64Le(bad_reserved_region[104..112], 0x0000_0000_7D00_1FFE);
    checksum.finishSum8Prefix(bad_reserved_region[0..], 9, bad_reserved_region.len);
    try std.testing.expectError(error.InvalidReservedMemoryRegion, parseDmar(bad_reserved_region[0..]));

    var unknown_segment = validDmar();
    endian.writeU16Le(unknown_segment[94..96], 1);
    checksum.finishSum8Prefix(unknown_segment[0..], 9, unknown_segment.len);
    try std.testing.expectError(error.InvalidReservedMemoryRegion, parseDmar(unknown_segment[0..]));
}

test "DMAR parser validates ATS capability scopes" {
    var all_ports = [_]u8{0} ** ATSR_MIN_BYTES;
    endian.writeU16Le(all_ports[0..2], ATSR_TYPE);
    endian.writeU16Le(all_ports[2..4], all_ports.len);
    all_ports[4] = ATSR_FLAG_ALL_PORTS;
    try std.testing.expectEqual(@as(u16, 0), try validateAtsCapability(all_ports[0..]));

    var bridge = [_]u8{0} ** (ATSR_MIN_BYTES + DEVICE_SCOPE_MIN_BYTES);
    endian.writeU16Le(bridge[0..2], ATSR_TYPE);
    endian.writeU16Le(bridge[2..4], bridge.len);
    bridge[8] = DEVICE_SCOPE_TYPE_PCI_SUB_HIERARCHY;
    bridge[9] = DEVICE_SCOPE_MIN_BYTES;
    bridge[14] = 1;
    try std.testing.expectEqual(@as(u16, 0), try validateAtsCapability(bridge[0..]));

    bridge[8] = DEVICE_SCOPE_TYPE_PCI_ENDPOINT;
    try std.testing.expectError(error.InvalidDeviceScope, validateAtsCapability(bridge[0..]));
}
