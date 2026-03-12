const std = @import("std");
const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");
const paging = @import("../memory/paging.zig");
const gdt = @import("../interrupts/gdt.zig");
const numfmt = @import("../utils/numfmt.zig");
const console = @import("../utils/console.zig");
const delay = @import("../utils/delay.zig");

pub const Spinlock = struct {
    locked: u32 = 0,

    pub fn acquire(self: *Spinlock) void {
        while (@cmpxchgWeak(u32, &self.locked, 0, 1, .acquire, .monotonic) != null) {
            while (@atomicLoad(u32, &self.locked, .monotonic) != 0) {
                asm volatile ("pause");
            }
        }
    }

    pub fn release(self: *Spinlock) void {
        @atomicStore(u32, &self.locked, 0, .release);
    }
};

pub var scheduler_lock: Spinlock = .{};

const APIC_BASE_MSR = 0x1B;
const APIC_BASE_ENABLE = 1 << 11;

const LOCAL_APIC_ID = 0x20;
const LOCAL_APIC_TPR = 0x80;
const LOCAL_APIC_EOI = 0xB0;
const LOCAL_APIC_SPURIOUS = 0xF0;
const LOCAL_APIC_ICR_LOW = 0x300;
const LOCAL_APIC_ICR_HIGH = 0x310;
const LOCAL_APIC_TIMER = 0x320;
const LOCAL_APIC_TIMER_INIT = 0x380;
const LOCAL_APIC_TIMER_DIV = 0x3E0;
const LOCAL_APIC_ICR_DELIVERY_STATUS = 1 << 12;

const IOAPIC_REGSEL = 0x00;
const IOAPIC_REGWIN = 0x10;
const APIC_MMIO_SIZE: u32 = 0x1000;
const AP_TRAMPOLINE_ADDR: usize = 0x8000;
const AP_STARTUP_VECTOR: u32 = AP_TRAMPOLINE_ADDR >> 12;
const AP_BOOT_TIMEOUT_LOOPS: u32 = 1_000_000;
const APIC_ICR_IDLE_TIMEOUT_LOOPS: u32 = 10_000;

pub const CPUInfo = struct {
    id: u32,
    apic_id: u32,
    is_bsp: bool,
    is_active: bool,
    stack: [*]u8,
    tss: *TSS,
    gdt: [8]gdt.GdtEntry,
    idle_task: ?*anyopaque,
};

const TSS = extern struct {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
};

const RSDP = extern struct {
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

const ACPIHeader = extern struct {
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

const RSDT = extern struct {
    header: ACPIHeader,
};

const XSDT = extern struct {
    header: ACPIHeader,
};

const MADT = extern struct {
    header: ACPIHeader,
    local_apic_addr: u32,
    flags: u32,
};

const MADTEntry = extern struct {
    entry_type: u8,
    length: u8,
};

const LocalAPICEntry = extern struct {
    header: MADTEntry,
    processor_id: u8,
    apic_id: u8,
    flags: u32,
};

const IOAPICEntry = extern struct {
    header: MADTEntry,
    ioapic_id: u8,
    reserved: u8,
    ioapic_addr: u32,
    global_system_interrupt_base: u32,
};

const MPFloatingPointer = extern struct {
    signature: [4]u8,
    config_table_addr: u32,
    length: u8,
    spec_rev: u8,
    checksum: u8,
    feature1: u8,
    feature2: u8,
    feature3: u8,
    feature4: u8,
    feature5: u8,
};

const MPConfigHeader = extern struct {
    signature: [4]u8,
    base_table_length: u16,
    spec_rev: u8,
    checksum: u8,
    oem_id: [8]u8,
    product_id: [12]u8,
    oem_table_ptr: u32,
    oem_table_size: u16,
    entry_count: u16,
    local_apic_addr: u32,
    extended_table_length: u16,
    extended_table_checksum: u8,
    reserved: u8,
};

const MPProcessorEntry = extern struct {
    entry_type: u8,
    local_apic_id: u8,
    local_apic_version: u8,
    cpu_flags: u8,
    cpu_signature: u32,
    feature_flags: u32,
    reserved: [2]u32,
};

const MPIOAPICEntry = extern struct {
    entry_type: u8,
    ioapic_id: u8,
    ioapic_version: u8,
    ioapic_flags: u8,
    ioapic_addr: u32,
};

const APBootTarget = extern struct {
    apic_id: u32,
    stack_top: u32,
    cpu_id: u32,
};

const APBringupState = enum(u32) {
    hold = 0,
    online = 1,
    abort = 2,
};

const MAX_CPUS = 16;
// SAFETY: entries populated during SMP discovery; num_cpus tracks valid entries
var cpu_info: [MAX_CPUS]CPUInfo = undefined;
var num_cpus: u32 = 0;
var active_cpus: u32 = 1;
var cpus_started: u32 = 0;
var smp_enabled: bool = false;
var smp_prepared: bool = false;

var local_apic_base: usize = 0;
var ioapic_base: usize = 0;
var ap_bringup_state: u32 = @intFromEnum(APBringupState.hold);
var ap_boot_targets: [MAX_CPUS - 1]APBootTarget = undefined;

extern var ap_trampoline_start: u8;
extern var ap_trampoline_end: u8;
extern var ap_trampoline_boot_cr3: u32;
extern var ap_trampoline_target_table: u32;
extern var ap_trampoline_target_count: u32;
extern var ap_trampoline_local_apic_base: u32;
extern var ap_trampoline_ap_main: u32;

pub fn init() void {
    vga.print("Initializing SMP support...\n");
    resetState();

    if (!detectAPIC()) {
        vga.print("No APIC detected, SMP not available\n");
        return;
    }

    enableLocalAPIC();
    parseACPI();
    parseMPTables();
    fallbackEnumerateFromCPUID();
    ensureBSPEntry();
    normalizeCPUOrdering();

    if (num_cpus > 1) {
        vga.print("Found ");
        numfmt.printDec(num_cpus);
        vga.print(" CPUs\n");

        if (!setupAPTrampoline()) {
            vga.print("AP trampoline setup failed, SMP startup disabled\n");
            return;
        }

        smp_prepared = true;
        vga.print("SMP bring-up prepared\n");
    } else {
        vga.print("Single CPU system\n");
    }
}

pub fn startSecondaryCPUs() void {
    if (!smp_prepared or num_cpus <= 1 or smp_enabled) return;

    console.print("Starting application processors...\n");
    prepareAPIdleProcesses();
    console.print("AP idle tasks prepared\n");

    @atomicStore(u32, &ap_bringup_state, @intFromEnum(APBringupState.hold), .release);
    const all_started = startAPs();
    active_cpus = countContiguousActiveCPUs();

    if (active_cpus > 1) {
        smp_enabled = true;
        @atomicStore(u32, &ap_bringup_state, @intFromEnum(APBringupState.online), .release);
        if (!all_started) {
            console.print("SMP partial bring-up active on ");
            printConsoleDec(active_cpus);
            console.print(" CPUs\n");
        }
    } else {
        active_cpus = 1;
        @atomicStore(u32, &ap_bringup_state, @intFromEnum(APBringupState.abort), .release);
        console.print("AP bring-up incomplete, continuing on BSP only\n");
    }
}

fn resetState() void {
    num_cpus = 0;
    active_cpus = 1;
    @atomicStore(u32, &cpus_started, 0, .release);
    smp_enabled = false;
    smp_prepared = false;
    ioapic_base = 0;
    @atomicStore(u32, &ap_bringup_state, @intFromEnum(APBringupState.hold), .release);
}

fn detectAPIC() bool {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [eax_in] "{eax}" (1),
    );

    return (edx & (1 << 9)) != 0;
}

fn detectLogicalCPUCount() u32 {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [eax_in] "{eax}" (1),
    );

    const logical_count = (ebx >> 16) & 0xFF;
    return if (logical_count == 0) 1 else logical_count;
}

fn enableLocalAPIC() void {
    const apic_base = rdmsr(APIC_BASE_MSR);
    local_apic_base = @as(usize, @intCast(apic_base & 0xFFFFF000));
    mapApicMmio(local_apic_base);

    wrmsr(APIC_BASE_MSR, apic_base | APIC_BASE_ENABLE);

    writeLocalAPIC(LOCAL_APIC_SPURIOUS, readLocalAPIC(LOCAL_APIC_SPURIOUS) | 0x100);
    writeLocalAPIC(LOCAL_APIC_TPR, 0);

    writeLocalAPIC(LOCAL_APIC_TIMER_DIV, 0x3);
    writeLocalAPIC(LOCAL_APIC_TIMER_INIT, 0xFFFFFFFF);
    writeLocalAPIC(LOCAL_APIC_TIMER, 0x20 | 0x20000);

    vga.print("Local APIC enabled at 0x");
    numfmt.printHex(local_apic_base);
    vga.print("\n");
}

fn mapApicMmio(base: usize) void {
    if (base == 0) return;

    const aligned_base: u32 = @intCast(base & ~@as(usize, 0xFFF));
    const flags = paging.PAGE_PRESENT |
        paging.PAGE_WRITABLE |
        paging.PAGE_WRITE_THROUGH |
        paging.PAGE_CACHE_DISABLE |
        paging.PAGE_GLOBAL;

    paging.map_range(aligned_base, aligned_base, APIC_MMIO_SIZE, flags);
}

fn parseACPI() void {
    const rsdp = findRSDP() orelse {
        vga.print("ACPI RSDP not found\n");
        return;
    };

    if (rsdp.revision >= 2 and rsdp.xsdt_address != 0) {
        if (std.math.cast(usize, rsdp.xsdt_address)) |xsdt_addr| {
            if ((xsdt_addr & 0x7) == 0 and parseRootTableXSDT(@ptrFromInt(xsdt_addr))) {
                return;
            }
        }
    }

    if ((rsdp.rsdt_address & 0x3) == 0) {
        _ = parseRootTableRSDT(@ptrFromInt(rsdp.rsdt_address));
    }
}

fn parseRootTableRSDT(rsdt: *align(1) const RSDT) bool {
    const num_entries = (rsdt.header.length - @sizeOf(ACPIHeader)) / @sizeOf(u32);
    var i: u32 = 0;
    while (i < num_entries) : (i += 1) {
        const table_addr = readRsdtEntry(rsdt, i);
        if (tryParseMADT(table_addr)) return true;
    }
    return false;
}

fn parseRootTableXSDT(xsdt: *align(1) const XSDT) bool {
    const num_entries = (xsdt.header.length - @sizeOf(ACPIHeader)) / @sizeOf(u64);
    var i: u32 = 0;
    while (i < num_entries) : (i += 1) {
        const table_addr = readXsdtEntry(xsdt, i);
        if (table_addr != 0 and tryParseMADT(table_addr)) return true;
    }
    return false;
}

fn tryParseMADT(table_addr: usize) bool {
    const table: *align(1) const ACPIHeader = @ptrFromInt(table_addr);
    if (!std.mem.eql(u8, &table.signature, "APIC")) return false;

    const madt_ptr: *align(1) const MADT = @ptrFromInt(table_addr);
    parseMADT(madt_ptr);
    return true;
}

fn findRSDP() ?*align(1) const RSDP {
    const ebda_segment: *align(1) const u16 = @ptrFromInt(0x40E);
    const ebda_addr = @as(usize, ebda_segment.*) << 4;
    var scan_addr = ebda_addr;
    const ebda_end = ebda_addr + 1024;
    while (scan_addr < ebda_end) : (scan_addr += 16) {
        const rsdp: *align(1) const RSDP = @ptrFromInt(scan_addr);
        if (isValidRSDP(rsdp)) return rsdp;
    }

    scan_addr = 0xE0000;
    while (scan_addr < 0x100000) : (scan_addr += 16) {
        const rsdp: *align(1) const RSDP = @ptrFromInt(scan_addr);
        if (isValidRSDP(rsdp)) return rsdp;
    }

    return null;
}

fn isValidRSDP(rsdp: *align(1) const RSDP) bool {
    if (!std.mem.eql(u8, &rsdp.signature, "RSD PTR ")) return false;
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

fn validateChecksum(data: [*]const u8, length: usize) bool {
    var sum: u8 = 0;
    for (0..length) |i| {
        sum +%= data[i];
    }
    return sum == 0;
}

fn parseMADT(madt: *align(1) const MADT) void {
    local_apic_base = madt.local_apic_addr;
    mapApicMmio(local_apic_base);

    var entry_ptr = @intFromPtr(madt) + @sizeOf(MADT);
    const table_end = @intFromPtr(madt) + madt.header.length;
    const bsp_apic_id = readLocalAPIC(LOCAL_APIC_ID) >> 24;

    while (entry_ptr < table_end) {
        const entry: *align(1) const MADTEntry = @ptrFromInt(entry_ptr);
        if (entry.length < @sizeOf(MADTEntry)) break;

        switch (entry.entry_type) {
            0 => {
                const lapic: *align(1) const LocalAPICEntry = @ptrFromInt(entry_ptr);
                if ((lapic.flags & 1) != 0 and num_cpus < MAX_CPUS) {
                    cpu_info[num_cpus] = CPUInfo{
                        .id = num_cpus,
                        .apic_id = lapic.apic_id,
                        .is_bsp = lapic.apic_id == bsp_apic_id,
                        .is_active = lapic.apic_id == bsp_apic_id,
                        .stack = undefined,
                        .tss = undefined,
                        .gdt = undefined,
                        .idle_task = null,
                    };
                    num_cpus += 1;
                }
            },
            1 => {
                const ioapic: *align(1) const IOAPICEntry = @ptrFromInt(entry_ptr);
                ioapic_base = ioapic.ioapic_addr;
                mapApicMmio(ioapic_base);
            },
            else => {},
        }

        entry_ptr += entry.length;
    }
}

fn ensureBSPEntry() void {
    const bsp_apic_id = readLocalAPIC(LOCAL_APIC_ID) >> 24;
    for (cpu_info[0..num_cpus]) |*cpu| {
        if (cpu.apic_id == bsp_apic_id) {
            cpu.is_bsp = true;
            cpu.is_active = true;
            if (num_cpus == 0) num_cpus = 1;
            return;
        }
    }

    if (num_cpus >= MAX_CPUS) return;

    cpu_info[num_cpus] = CPUInfo{
        .id = num_cpus,
        .apic_id = bsp_apic_id,
        .is_bsp = true,
        .is_active = true,
        .stack = undefined,
        .tss = undefined,
        .gdt = undefined,
        .idle_task = null,
    };
    num_cpus += 1;
}

fn fallbackEnumerateFromCPUID() void {
    const logical_count = @min(detectLogicalCPUCount(), MAX_CPUS);
    if (logical_count <= num_cpus or logical_count <= 1) return;

    if (num_cpus == 0) {
        vga.print("Falling back to CPUID CPU enumeration\n");
    } else {
        vga.print("Extending CPU inventory from CPUID fallback\n");
    }

    var i = num_cpus;
    while (i < logical_count) : (i += 1) {
        cpu_info[i] = CPUInfo{
            .id = i,
            .apic_id = i,
            .is_bsp = i == 0,
            .is_active = i == 0,
            .stack = undefined,
            .tss = undefined,
            .gdt = undefined,
            .idle_task = null,
        };
    }
    num_cpus = logical_count;
}

fn parseMPTables() void {
    if (num_cpus > 1) return;

    const mp = findMPFloatingPointer() orelse return;
    if (mp.config_table_addr == 0 or (mp.config_table_addr & 0x3) != 0) return;

    const config: *align(1) const MPConfigHeader = @ptrFromInt(mp.config_table_addr);
    if (!std.mem.eql(u8, &config.signature, "PCMP")) return;
    if (!validateChecksum(@ptrCast(config), config.base_table_length)) return;

    num_cpus = 0;
    local_apic_base = config.local_apic_addr;
    mapApicMmio(local_apic_base);

    var entry_ptr = @intFromPtr(config) + @sizeOf(MPConfigHeader);
    var remaining_entries = config.entry_count;
    while (remaining_entries > 0) : (remaining_entries -= 1) {
        const entry_type = @as(*align(1) const u8, @ptrFromInt(entry_ptr)).*;
        switch (entry_type) {
            0 => {
                const proc: *align(1) const MPProcessorEntry = @ptrFromInt(entry_ptr);
                if ((proc.cpu_flags & 0x1) != 0 and num_cpus < MAX_CPUS) {
                    cpu_info[num_cpus] = CPUInfo{
                        .id = num_cpus,
                        .apic_id = proc.local_apic_id,
                        .is_bsp = (proc.cpu_flags & 0x2) != 0,
                        .is_active = (proc.cpu_flags & 0x2) != 0,
                        .stack = undefined,
                        .tss = undefined,
                        .gdt = undefined,
                        .idle_task = null,
                    };
                    num_cpus += 1;
                }
                entry_ptr += @sizeOf(MPProcessorEntry);
            },
            2 => {
                const ioapic: *align(1) const MPIOAPICEntry = @ptrFromInt(entry_ptr);
                if ((ioapic.ioapic_flags & 0x1) != 0) {
                    ioapic_base = ioapic.ioapic_addr;
                    mapApicMmio(ioapic_base);
                }
                entry_ptr += @sizeOf(MPIOAPICEntry);
            },
            1, 3, 4 => entry_ptr += 8,
            else => break,
        }
    }

    if (num_cpus > 1) {
        vga.print("Loaded CPU topology from MP tables\n");
    }
}

fn findMPFloatingPointer() ?*align(1) const MPFloatingPointer {
    const ebda_segment: *align(1) const u16 = @ptrFromInt(0x40E);
    const ebda_addr = @as(usize, ebda_segment.*) << 4;
    if (scanMPRange(ebda_addr, ebda_addr + 1024)) |mp| return mp;

    const base_kb: *align(1) const u16 = @ptrFromInt(0x413);
    const base_mem_end = @as(usize, base_kb.*) * 1024;
    if (base_mem_end >= 1024) {
        if (scanMPRange(base_mem_end - 1024, base_mem_end)) |mp| return mp;
    }

    return scanMPRange(0xF0000, 0x100000);
}

fn scanMPRange(start: usize, end: usize) ?*align(1) const MPFloatingPointer {
    var addr = start;
    while (addr + @sizeOf(MPFloatingPointer) <= end) : (addr += 16) {
        const mp: *align(1) const MPFloatingPointer = @ptrFromInt(addr);
        if (std.mem.eql(u8, &mp.signature, "_MP_") and validateChecksum(@ptrCast(mp), mp.length * 16)) {
            return mp;
        }
    }
    return null;
}

fn normalizeCPUOrdering() void {
    if (num_cpus == 0) return;

    var bsp_index: usize = 0;
    while (bsp_index < num_cpus and !cpu_info[bsp_index].is_bsp) : (bsp_index += 1) {}
    if (bsp_index >= num_cpus) return;

    if (bsp_index != 0) {
        const tmp = cpu_info[0];
        cpu_info[0] = cpu_info[bsp_index];
        cpu_info[bsp_index] = tmp;
    }

    var i: usize = 0;
    while (i < num_cpus) : (i += 1) {
        cpu_info[i].id = @intCast(i);
        if (i == 0) {
            cpu_info[i].is_bsp = true;
            cpu_info[i].is_active = true;
        }
    }
}

fn readRsdtEntry(rsdt: *align(1) const RSDT, index: usize) u32 {
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

fn setupAPTrampoline() bool {
    const trampoline_start = @intFromPtr(&ap_trampoline_start);
    const trampoline_end = @intFromPtr(&ap_trampoline_end);
    if (trampoline_end <= trampoline_start) return false;

    const trampoline_size = trampoline_end - trampoline_start;
    @memcpy(
        @as([*]u8, @ptrFromInt(AP_TRAMPOLINE_ADDR))[0..trampoline_size],
        @as([*]const u8, @ptrFromInt(trampoline_start))[0..trampoline_size],
    );

    const stack_size = 16 * 1024;
    for (1..num_cpus) |i| {
        const stack_mem = memory.kmalloc(stack_size) orelse unreachable;
        cpu_info[i].stack = @as([*]u8, @ptrCast(stack_mem)) + stack_size;

        const tss_mem = memory.kmalloc(@sizeOf(TSS) + @alignOf(TSS) - 1) orelse unreachable;
        const tss_addr = std.mem.alignForward(usize, @intFromPtr(tss_mem), @alignOf(TSS));
        cpu_info[i].tss = @ptrFromInt(tss_addr);
        cpu_info[i].tss.rsp0 = @intFromPtr(cpu_info[i].stack);

        ap_boot_targets[i - 1] = .{
            .apic_id = cpu_info[i].apic_id,
            .stack_top = @truncate(@intFromPtr(cpu_info[i].stack)),
            .cpu_id = @intCast(i),
        };
    }

    const cr3 = asm volatile (
        \\mov %%cr3, %[result]
        : [result] "=r" (-> usize),
    );

    patchTrampolineU32(trampoline_start, @intFromPtr(&ap_trampoline_boot_cr3), @truncate(cr3));
    patchTrampolineU32(trampoline_start, @intFromPtr(&ap_trampoline_target_table), @truncate(@intFromPtr(&ap_boot_targets)));
    patchTrampolineU32(trampoline_start, @intFromPtr(&ap_trampoline_target_count), num_cpus - 1);
    patchTrampolineU32(trampoline_start, @intFromPtr(&ap_trampoline_local_apic_base), @intCast(local_apic_base));
    patchTrampolineU32(trampoline_start, @intFromPtr(&ap_trampoline_ap_main), @truncate(@intFromPtr(&ap_main)));
    return true;
}

fn patchTrampolineU32(trampoline_start: usize, symbol_addr: usize, value: u32) void {
    const offset = symbol_addr - trampoline_start;
    const patch_ptr: *align(1) u32 = @ptrFromInt(AP_TRAMPOLINE_ADDR + offset);
    patch_ptr.* = value;
}

fn prepareAPIdleProcesses() void {
    const process_mod = @import("../process/process.zig");
    const scheduler = @import("../process/scheduler.zig");

    for (1..num_cpus) |i| {
        if (cpu_info[i].idle_task != null) continue;

        const idle_proc = process_mod.create_kernel_process("idle-ap", apIdleTask);
        scheduler.assignProcessToCPU(idle_proc, @intCast(i));
        cpu_info[i].idle_task = @ptrCast(idle_proc);
    }
}

fn startAPs() bool {
    @atomicStore(u32, &cpus_started, 0, .release);
    for (1..num_cpus) |i| {
        setCPUActive(@intCast(i), false);
    }

    var all_started = true;
    for (1..num_cpus) |i| {
        console.print("Starting CPU ");
        printConsoleDec(@as(u32, @intCast(i)));
        console.print("...\n");

        startAP(@intCast(i));

        var timeout = AP_BOOT_TIMEOUT_LOOPS;
        while (!isCPUActive(@intCast(i)) and timeout > 0) : (timeout -= 1) {
            asm volatile ("pause");
        }

        if (isCPUActive(@intCast(i))) {
            console.print("CPU ");
            printConsoleDec(@as(u32, @intCast(i)));
            console.print(" started\n");
        } else {
            all_started = false;
            console.print("CPU ");
            printConsoleDec(@as(u32, @intCast(i)));
            console.print(" failed to start\n");
        }
    }
    return all_started;
}

fn startAP(cpu_id: u32) void {
    const apic_id = cpu_info[cpu_id].apic_id;
    if (!sendApicCommand(apic_id, 0x00C500)) return;
    busyWait(10000);
    if (!sendApicCommand(apic_id, 0x008500)) return;
    busyWait(200);
    if (!sendApicCommand(apic_id, 0x000600 | AP_STARTUP_VECTOR)) return;
    busyWait(200);
    _ = sendApicCommand(apic_id, 0x000600 | AP_STARTUP_VECTOR);
}

fn sendApicCommand(apic_id: u32, low: u32) bool {
    if (!waitForIcrIdle()) return false;
    writeLocalAPIC(LOCAL_APIC_ICR_HIGH, apic_id << 24);
    writeLocalAPIC(LOCAL_APIC_ICR_LOW, low);
    return waitForIcrIdle();
}

fn waitForIcrIdle() bool {
    var timeout: u32 = APIC_ICR_IDLE_TIMEOUT_LOOPS;
    while ((readLocalAPIC(LOCAL_APIC_ICR_LOW) & LOCAL_APIC_ICR_DELIVERY_STATUS) != 0 and timeout > 0) : (timeout -= 1) {
        asm volatile ("pause");
    }
    return timeout > 0;
}

fn setCPUActive(cpu_id: u32, active: bool) void {
    @atomicStore(bool, &cpu_info[cpu_id].is_active, active, .release);
}

fn isCPUActive(cpu_id: u32) bool {
    return @atomicLoad(bool, &cpu_info[cpu_id].is_active, .acquire);
}

pub export fn ap_main(cpu_id: u32) void {
    enableLocalAPIC();
    setCPUActive(cpu_id, true);
    _ = @atomicRmw(u32, &cpus_started, .Add, 1, .acq_rel);

    while (true) {
        switch (@as(APBringupState, @enumFromInt(@atomicLoad(u32, &ap_bringup_state, .acquire)))) {
            .hold => asm volatile ("pause"),
            .abort => {
                while (true) {
                    asm volatile ("hlt");
                }
            },
            .online => break,
        }
    }

    const process_mod = @import("../process/process.zig");
    const idle_proc = cpu_info[cpu_id].idle_task orelse {
        while (true) {
            asm volatile ("hlt");
        }
    };

    process_mod.setPerCPUCurrent(cpu_id, @ptrCast(@alignCast(idle_proc)));
    asm volatile ("sti");

    while (true) {
        process_mod.yield();
        asm volatile ("hlt");
    }
}

fn apIdleTask() void {
    while (true) {
        asm volatile ("hlt");
    }
}

fn readLocalAPIC(reg: u32) u32 {
    return @as(*volatile u32, @ptrFromInt(local_apic_base + reg)).*;
}

fn writeLocalAPIC(reg: u32, value: u32) void {
    @as(*volatile u32, @ptrFromInt(local_apic_base + reg)).* = value;
}

fn rdmsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;

    asm volatile (
        \\rdmsr
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );

    return (@as(u64, high) << 32) | low;
}

fn wrmsr(msr: u32, value: u64) void {
    const low: u32 = @truncate(value);
    const high: u32 = @truncate(value >> 32);

    asm volatile (
        \\wrmsr
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
    );
}

fn busyWait(microseconds: u32) void {
    delay.busyWait(microseconds);
}

fn printConsoleDec(value: u32) void {
    if (value == 0) {
        console.print("0");
        return;
    }

    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var current = value;

    while (current > 0) : (current /= 10) {
        digits[count] = @as(u8, @intCast('0' + (current % 10)));
        count += 1;
    }

    while (count > 0) {
        count -= 1;
        console.printChar(digits[count]);
    }
}

fn countContiguousActiveCPUs() u32 {
    var count: u32 = 1;
    while (count < num_cpus and isCPUActive(count)) : (count += 1) {}
    return count;
}

pub fn getCurrentCPU() u32 {
    const apic_id = readLocalAPIC(LOCAL_APIC_ID) >> 24;
    for (cpu_info[0..num_cpus]) |*cpu| {
        if (cpu.apic_id == apic_id) {
            return cpu.id;
        }
    }
    return 0;
}

pub fn sendIPI(target_cpu: u32, vector: u8) void {
    if (target_cpu >= num_cpus) return;
    sendApicCommand(cpu_info[target_cpu].apic_id, vector);
}

pub fn broadcastIPI(vector: u8) void {
    _ = waitForIcrIdle();
    writeLocalAPIC(LOCAL_APIC_ICR_HIGH, 0);
    writeLocalAPIC(LOCAL_APIC_ICR_LOW, 0x000C0000 | vector);
    _ = waitForIcrIdle();
}

pub fn endOfInterrupt() void {
    writeLocalAPIC(LOCAL_APIC_EOI, 0);
}

pub fn getNumCPUs() u32 {
    return num_cpus;
}

pub fn getActiveCPUCount() u32 {
    return if (smp_enabled) active_cpus else 1;
}

pub fn isSMPEnabled() bool {
    return smp_enabled;
}
