const std = @import("std");
const tables = @import("tables.zig");
const vga = @import("../drivers/vga.zig");
const io = @import("../utils/io.zig");
const delay = @import("../utils/delay.zig");

const FADT_SIGNATURE = "FACP";
const DSDT_SIGNATURE = "DSDT";

const ACPIHeader = tables.ACPIHeader;
const RootTable = tables.RootTable;

pub const FADT = extern struct {
    header: ACPIHeader,
    firmware_ctrl: u32,
    dsdt: u32,
    reserved: u8,
    preferred_pm_profile: u8,
    sci_int: u16,
    smi_cmd: u32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_ctrl: u8,
    pm1a_evt_blk: u32,
    pm1b_evt_blk: u32,
    pm1a_ctrl_blk: u32,
    pm1b_ctrl_blk: u32,
    pm2_ctrl_blk: u32,
    pm_timer_blk: u32,
    gpe0_blk: u32,
    gpe1_blk: u32,
    pm1_evt_len: u8,
    pm1_ctrl_len: u8,
    pm2_ctrl_len: u8,
    pm_timer_len: u8,
    gpe0_blk_len: u8,
    gpe1_blk_len: u8,
    gpe1_base: u8,
    cstate_ctrl: u8,
    worst_c2_latency: u16,
    worst_c3_latency: u16,
    flush_size: u16,
    flush_stride: u16,
    duty_offset: u8,
    duty_width: u8,
    day_alarm: u8,
    month_alarm: u8,
    century: u8,
    boot_arch_flags: u16,
    reserved2: u8,
    flags: u32,
    reset_reg: GenericAddress,
    reset_value: u8,
    arm_boot_arch: u16,
    fadt_minor_version: u8,
    x_firmware_ctrl: u64,
    x_dsdt: u64,
    x_pm1a_evt_blk: GenericAddress,
    x_pm1b_evt_blk: GenericAddress,
    x_pm1a_ctrl_blk: GenericAddress,
    x_pm1b_ctrl_blk: GenericAddress,
    x_pm2_ctrl_blk: GenericAddress,
    x_pm_timer_blk: GenericAddress,
    x_gpe0_blk: GenericAddress,
    x_gpe1_blk: GenericAddress,
};

pub const GenericAddress = extern struct {
    address_space: u8,
    bit_width: u8,
    bit_offset: u8,
    access_size: u8,
    address: u64,
};

const PM1_CTRL_SLP_TYP_SHIFT = 10;
const PM1_CTRL_SLP_EN = 1 << 13;

pub const PowerState = enum {
    S0_Working,
    S1_Sleep,
    S3_Suspend,
    S4_Hibernate,
    S5_Shutdown,
};

var rsdp_ptr: ?*align(1) const tables.RSDP = null;
var root_table: ?RootTable = null;
var fadt_ptr: ?*align(1) const FADT = null;
var pm1a_control: u32 = 0;
var pm1b_control: u32 = 0;
var slp_typa: [6]u16 = [_]u16{0} ** 6;
var slp_typb: [6]u16 = [_]u16{0} ** 6;
var smi_cmd: u32 = 0;
var acpi_enable_cmd: u8 = 0;
var is_enabled: bool = false;

pub fn init() void {
    vga.print("Initializing ACPI power management...\n");

    if (!findRSDP()) {
        vga.print("ACPI not available\n");
        return;
    }

    if (!parseRSDT()) {
        vga.print("Failed to parse ACPI tables\n");
        return;
    }

    if (!parseFADT()) {
        vga.print("Failed to parse FADT\n");
        return;
    }

    parseDSDT();
    enableACPI();

    vga.print("ACPI initialized successfully\n");
}

fn findRSDP() bool {
    const rsdp = tables.findRSDP() orelse return false;
    rsdp_ptr = rsdp;
    vga.print("Found RSDP at 0x");
    printHex(@intFromPtr(rsdp));
    vga.print("\n");
    return true;
}

fn parseRSDT() bool {
    const rsdp = rsdp_ptr orelse return false;
    root_table = tables.selectRootTable(rsdp) orelse return false;
    vga.print(switch (root_table.?) {
        .xsdt => "Using XSDT\n",
        .rsdt => "Using RSDT\n",
    });
    return true;
}

fn parseFADT() bool {
    const root = root_table orelse return false;
    for (0..tables.entryCount(root)) |i| {
        const table_addr = tables.readEntry(root, i);
        if (table_addr == 0) continue;

        const table: *align(1) const ACPIHeader = @ptrFromInt(table_addr);
        if (std.mem.eql(u8, &table.signature, FADT_SIGNATURE)) {
            fadt_ptr = @ptrFromInt(table_addr);
            break;
        }
    }

    if (fadt_ptr) |fadt| {
        pm1a_control = fadt.pm1a_ctrl_blk;
        pm1b_control = fadt.pm1b_ctrl_blk;
        smi_cmd = fadt.smi_cmd;
        acpi_enable_cmd = fadt.acpi_enable;

        vga.print("FADT found: PM1a=0x");
        printHex(pm1a_control);
        vga.print(" PM1b=0x");
        printHex(pm1b_control);
        vga.print("\n");

        return true;
    }

    return false;
}

fn parseDSDT() void {
    const fadt = fadt_ptr orelse return;

    const dsdt_addr = blk: {
        if (std.math.cast(usize, fadt.x_dsdt)) |addr| {
            if (addr != 0) break :blk addr;
        }
        break :blk fadt.dsdt;
    };

    if (dsdt_addr == 0) return;

    const dsdt: *align(1) const ACPIHeader = @ptrFromInt(dsdt_addr);
    if (!std.mem.eql(u8, &dsdt.signature, DSDT_SIGNATURE)) {
        return;
    }

    vga.print("DSDT found at 0x");
    printHex(dsdt_addr);
    vga.print("\n");

    parseAML(@as([*]u8, @ptrFromInt(dsdt_addr + @sizeOf(ACPIHeader))), dsdt.length - @sizeOf(ACPIHeader));
}

fn parseAML(aml: [*]u8, length: u32) void {
    var offset: u32 = 0;

    while (offset < length) {
        const opcode = aml[offset];

        if (opcode == 0x08) {
            offset += 1;
            const name_offset = offset;
            offset += 4;

            if (std.mem.eql(u8, aml[name_offset .. name_offset + 4], "_S5_")) {
                offset += 1;

                if (aml[offset] == 0x12) {
                    offset += 1;
                    offset += 1;

                    if (aml[offset] == 0x0A) {
                        offset += 1;
                        slp_typa[5] = aml[offset];
                        offset += 1;
                    }

                    if (aml[offset] == 0x0A) {
                        offset += 1;
                        slp_typb[5] = aml[offset];
                        offset += 1;
                    }

                    vga.print("Found S5 sleep type: ");
                    printHex(slp_typa[5]);
                    vga.print("/");
                    printHex(slp_typb[5]);
                    vga.print("\n");
                }
            } else {
                offset += getAMLObjectSize(aml, offset);
            }
        } else {
            offset += 1;
        }
    }
}

fn getAMLObjectSize(aml: [*]u8, offset: u32) u32 {
    const opcode = aml[offset];

    switch (opcode) {
        0x00 => return 1,
        0x01 => return 1,
        0x08 => return 5,
        0x0A => return 2,
        0x0B => return 3,
        0x0C => return 5,
        0x0D => return aml[offset + 1] + 2,
        0x0E => return getPkgLength(aml, offset + 1) + 1,
        0x10 => return getPkgLength(aml, offset + 1) + 1,
        0x11 => return getPkgLength(aml, offset + 1) + 1,
        0x12 => return getPkgLength(aml, offset + 1) + 1,
        0x13 => return getPkgLength(aml, offset + 1) + 1,
        0x14 => return getPkgLength(aml, offset + 1) + 1,
        else => return 1,
    }
}

fn getPkgLength(aml: [*]u8, offset: u32) u32 {
    const lead_byte = aml[offset];

    if ((lead_byte & 0xC0) == 0) {
        return lead_byte;
    } else if ((lead_byte & 0xC0) == 0x40) {
        return ((@as(u32, aml[offset + 1]) << 4) | (lead_byte & 0x0F));
    } else if ((lead_byte & 0xC0) == 0x80) {
        return ((@as(u32, aml[offset + 2]) << 12) |
            (@as(u32, aml[offset + 1]) << 4) |
            (lead_byte & 0x0F));
    } else {
        return ((@as(u32, aml[offset + 3]) << 20) |
            (@as(u32, aml[offset + 2]) << 12) |
            (@as(u32, aml[offset + 1]) << 4) |
            (lead_byte & 0x0F));
    }
}

fn enableACPI() void {
    const fadt = fadt_ptr orelse return;

    if ((fadt.boot_arch_flags & 1) != 0) {
        vga.print("ACPI already enabled by BIOS\n");
        is_enabled = true;
        return;
    }

    if (smi_cmd != 0 and acpi_enable_cmd != 0) {
        io.outb(@as(u16, @intCast(smi_cmd)), acpi_enable_cmd);

        var timeout: u32 = 100;
        while (timeout > 0) : (timeout -= 1) {
            if ((io.inw(@as(u16, @intCast(pm1a_control))) & 1) != 0) {
                is_enabled = true;
                vga.print("ACPI enabled\n");
                return;
            }
            delay.busyWait(10000);
        }

        vga.print("Failed to enable ACPI\n");
    }
}

pub fn shutdown() void {
    if (!is_enabled) {
        vga.print("ACPI not enabled, cannot shutdown\n");
        return;
    }

    vga.print("Shutting down...\n");

    asm volatile ("cli");

    if (pm1a_control != 0) {
        const slp_typ = @as(u16, @intCast(slp_typa[5])) << PM1_CTRL_SLP_TYP_SHIFT;
        io.outw(@as(u16, @intCast(pm1a_control)), slp_typ | PM1_CTRL_SLP_EN);
    }

    if (pm1b_control != 0) {
        const slp_typ = @as(u16, @intCast(slp_typb[5])) << PM1_CTRL_SLP_TYP_SHIFT;
        io.outw(@as(u16, @intCast(pm1b_control)), slp_typ | PM1_CTRL_SLP_EN);
    }

    while (true) {
        asm volatile ("hlt");
    }
}

pub fn reboot() void {
    vga.print("Rebooting...\n");

    asm volatile ("cli");

    var tmp: u8 = io.inb(0x64);
    while ((tmp & 0x02) != 0) : (tmp = io.inb(0x64)) {}
    io.outb(0x64, 0xFE);

    io.outb(0xCF9, 0x06);

    while (true) {
        asm volatile ("hlt");
    }
}

fn printHex(value: usize) void {
    const hex_chars = "0123456789ABCDEF";
    // SAFETY: filled by the following hex digit extraction loop
    var buffer: [16]u8 = undefined;
    var i: usize = 0;
    var v = value;

    if (v == 0) {
        vga.printChar('0');
        return;
    }

    while (v > 0) : (v >>= 4) {
        buffer[i] = hex_chars[v & 0xF];
        i += 1;
    }

    while (i > 0) {
        i -= 1;
        vga.printChar(buffer[i]);
    }
}
