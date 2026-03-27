const std = @import("std");

const RSDP_SIGNATURE = "RSD PTR ";

pub const ACPIHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
};

pub const RSDP = extern struct {
    signature: [8]u8,
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,
    length: u32 = 0,
    xsdt_address: u64 = 0,
    extended_checksum: u8 = 0,
    reserved: [3]u8 = .{ 0, 0, 0 },
};

pub const RSDT = extern struct {
    header: ACPIHeader,
};

pub const XSDT = extern struct {
    header: ACPIHeader,
};

pub const RootTable = union(enum) {
    rsdt: *align(1) const RSDT,
    xsdt: *align(1) const XSDT,
};

pub fn validateChecksum(data: [*]const u8, length: usize) bool {
    var sum: u8 = 0;
    var i: usize = 0;
    while (i < length) : (i += 1) {
        sum +%= data[i];
    }
    return sum == 0;
}

pub fn findRSDP() ?*align(1) const RSDP {
    const ebda_segment: *align(1) const u16 = @ptrFromInt(0x40E);
    const ebda_addr = (@as(usize, ebda_segment.*) << 4) & ~@as(usize, 0xF);

    if (ebdaAddrLooksValid(ebda_addr)) {
        var scan_addr = ebda_addr;
        const ebda_end = ebda_addr + 1024;
        while (scan_addr < ebda_end) : (scan_addr += 16) {
            const rsdp: *align(1) const RSDP = @ptrFromInt(scan_addr);
            if (isValidRSDP(rsdp)) return rsdp;
        }
    }

    var scan_addr: usize = 0xE0000;
    while (scan_addr < 0x100000) : (scan_addr += 16) {
        const rsdp: *align(1) const RSDP = @ptrFromInt(scan_addr);
        if (isValidRSDP(rsdp)) return rsdp;
    }

    return null;
}

pub fn selectRootTable(rsdp: *align(1) const RSDP) ?RootTable {
    if (rsdp.revision >= 2 and rsdp.xsdt_address != 0) {
        if (std.math.cast(usize, rsdp.xsdt_address)) |xsdt_addr| {
            if ((xsdt_addr & 0x7) == 0) {
                return .{ .xsdt = @ptrFromInt(xsdt_addr) };
            }
        }
    }

    if (rsdp.rsdt_address != 0 and (rsdp.rsdt_address & 0x3) == 0) {
        return .{ .rsdt = @ptrFromInt(rsdp.rsdt_address) };
    }

    return null;
}

pub fn entryCount(root: RootTable) usize {
    return switch (root) {
        .rsdt => |rsdt| (rsdt.header.length - @sizeOf(ACPIHeader)) / @sizeOf(u32),
        .xsdt => |xsdt| (xsdt.header.length - @sizeOf(ACPIHeader)) / @sizeOf(u64),
    };
}

pub fn readEntry(root: RootTable, index: usize) usize {
    return switch (root) {
        .rsdt => |rsdt| readRsdtEntry(rsdt, index),
        .xsdt => |xsdt| readXsdtEntry(xsdt, index),
    };
}

fn ebdaAddrLooksValid(ebda_addr: usize) bool {
    return ebda_addr >= 0x80000 and ebda_addr < 0xA0000 and ebda_addr + 1024 <= 0xA0000;
}

fn isValidRSDP(rsdp: *align(1) const RSDP) bool {
    if (!std.mem.eql(u8, &rsdp.signature, RSDP_SIGNATURE)) return false;
    if (!validateChecksum(@ptrCast(rsdp), 20)) return false;

    const has_valid_rsdt = rsdp.rsdt_address != 0 and (rsdp.rsdt_address & 0x3) == 0;
    if (rsdp.revision < 2) return has_valid_rsdt;

    if (rsdp.length < @sizeOf(RSDP)) return false;
    if (!validateChecksum(@ptrCast(rsdp), rsdp.length)) return false;

    const has_valid_xsdt = if (rsdp.xsdt_address == 0)
        false
    else if (std.math.cast(usize, rsdp.xsdt_address)) |xsdt_addr|
        (xsdt_addr & 0x7) == 0
    else
        false;

    return has_valid_rsdt or has_valid_xsdt;
}

fn readRsdtEntry(rsdt: *align(1) const RSDT, index: usize) usize {
    const entries_base: [*]align(1) const u8 = @ptrCast(@as([*]align(1) const u8, @ptrCast(rsdt)) + @sizeOf(ACPIHeader));
    const offset = index * @sizeOf(u32);
    const bytes: *align(1) const [@sizeOf(u32)]u8 = @ptrCast(entries_base + offset);
    return std.mem.readInt(u32, bytes, .little);
}

fn readXsdtEntry(xsdt: *align(1) const XSDT, index: usize) usize {
    const entries_base: [*]align(1) const u8 = @ptrCast(@as([*]align(1) const u8, @ptrCast(xsdt)) + @sizeOf(ACPIHeader));
    const offset = index * @sizeOf(u64);
    const bytes: *align(1) const [@sizeOf(u64)]u8 = @ptrCast(entries_base + offset);
    return std.math.cast(usize, std.mem.readInt(u64, bytes, .little)) orelse 0;
}
