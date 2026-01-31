const std = @import("std");
const vga = @import("../drivers/vga.zig");
const memory = @import("../memory/memory.zig");
const gdt = @import("../interrupts/gdt.zig");

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

const IOAPIC_REGSEL = 0x00;
const IOAPIC_REGWIN = 0x10;

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

const MAX_CPUS = 16;
// SAFETY: entries populated in parseACPI; num_cpus tracks valid entries
var cpu_info: [MAX_CPUS]CPUInfo = undefined;
var num_cpus: u32 = 0;
var cpus_started: u32 = 0;
var smp_enabled: bool = false;

var local_apic_base: usize = 0;
var ioapic_base: usize = 0;

var ap_trampoline_start: u8 = 0;
var ap_trampoline_end: u8 = 0;
var ap_boot_stack: u64 = 0;
var ap_boot_cr3: u64 = 0;
var ap_boot_gdt: u64 = 0;

pub fn init() void {
    vga.print("Initializing SMP support...\n");

    if (!detectAPIC()) {
        vga.print("No APIC detected, SMP not available\n");
        return;
    }

    enableLocalAPIC();
    parseACPI();

    if (num_cpus > 1) {
        vga.print("Found ");
        printNumber(num_cpus);
        vga.print(" CPUs\n");
        setupAPTrampoline();
        startAPs();
        smp_enabled = true;
    } else {
        vga.print("Single CPU system\n");
    }
}

fn detectAPIC() bool {
    // SAFETY: populated by the subsequent cpuid instruction
    var eax: u32 = undefined;
    // SAFETY: populated by the subsequent cpuid instruction
    var ebx: u32 = undefined;
    // SAFETY: populated by the subsequent cpuid instruction
    var ecx: u32 = undefined;
    // SAFETY: populated by the subsequent cpuid instruction
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

fn enableLocalAPIC() void {
    const apic_base = rdmsr(APIC_BASE_MSR);
    local_apic_base = @as(usize, @intCast(apic_base & 0xFFFFF000));

    wrmsr(APIC_BASE_MSR, apic_base | APIC_BASE_ENABLE);

    writeLocalAPIC(LOCAL_APIC_SPURIOUS, readLocalAPIC(LOCAL_APIC_SPURIOUS) | 0x100);

    writeLocalAPIC(LOCAL_APIC_TPR, 0);

    const timer_div = 0x3;
    writeLocalAPIC(LOCAL_APIC_TIMER_DIV, timer_div);
    writeLocalAPIC(LOCAL_APIC_TIMER_INIT, 0xFFFFFFFF);
    writeLocalAPIC(LOCAL_APIC_TIMER, 0x20 | 0x20000);

    vga.print("Local APIC enabled at 0x");
    printHex(local_apic_base);
    vga.print("\n");
}

fn parseACPI() void {
    const rsdp = findRSDP() orelse {
        vga.print("ACPI RSDP not found\n");
        return;
    };

    const rsdt: *RSDT = @ptrFromInt(rsdp.rsdt_address);
    const num_entries = (rsdt.header.length - @sizeOf(ACPIHeader)) / 4;

    var i: u32 = 0;
    while (i < num_entries) : (i += 1) {
        const table: *ACPIHeader = @ptrFromInt(rsdt.entries[i]);
        if (std.mem.eql(u8, &table.signature, "APIC")) {
            const madt_ptr: *MADT = @ptrFromInt(rsdt.entries[i]);
            parseMADT(madt_ptr);
            break;
        }
    }
}

const RSDP = extern struct {
    signature: [8]u8,
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,
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
    entries: [*]u32,
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

fn findRSDP() ?*RSDP {
    var addr: usize = 0xE0000;
    while (addr < 0x100000) : (addr += 16) {
        const rsdp: *RSDP = @ptrFromInt(addr);
        if (std.mem.eql(u8, &rsdp.signature, "RSD PTR ")) {
            return rsdp;
        }
    }
    return null;
}

fn parseMADT(madt: *MADT) void {
    local_apic_base = madt.local_apic_addr;

    var entry_ptr = @intFromPtr(madt) + @sizeOf(MADT);
    const table_end = @intFromPtr(madt) + madt.header.length;

    while (entry_ptr < table_end) {
        const entry: *MADTEntry = @ptrFromInt(entry_ptr);

        switch (entry.entry_type) {
            0 => {
                const lapic: *LocalAPICEntry = @ptrFromInt(entry_ptr);
                if ((lapic.flags & 1) != 0) {
                    if (num_cpus < MAX_CPUS) {
                        cpu_info[num_cpus] = CPUInfo{
                            .id = num_cpus,
                            .apic_id = lapic.apic_id,
                            .is_bsp = (num_cpus == 0),
                            .is_active = false,
                            // SAFETY: allocated in setupAPTrampoline before the AP starts
                            .stack = undefined,
                            // SAFETY: configured in setupAPTrampoline before the AP starts
                            .tss = undefined,
                            // SAFETY: configured in setupAPTrampoline before the AP starts
                            .gdt = undefined,
                            .idle_task = null,
                        };
                        num_cpus += 1;
                    }
                }
            },
            1 => {
                const ioapic: *IOAPICEntry = @ptrFromInt(entry_ptr);
                ioapic_base = ioapic.ioapic_addr;
            },
            else => {},
        }

        entry_ptr += entry.length;
    }
}

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

fn setupAPTrampoline() void {
    const trampoline_addr = 0x8000;
    const trampoline_size = @intFromPtr(&ap_trampoline_end) - @intFromPtr(&ap_trampoline_start);

    @memcpy(
        @as([*]u8, @ptrFromInt(trampoline_addr))[0..trampoline_size],
        @as([*]u8, @ptrFromInt(@intFromPtr(&ap_trampoline_start)))[0..trampoline_size]
    );

    const stack_size = 16384;
    for (1..num_cpus) |i| {
        const stack_mem = memory.kmalloc(stack_size) orelse unreachable;
        cpu_info[i].stack = @as([*]u8, @ptrCast(stack_mem)) + stack_size;

        const tss_mem = memory.kmalloc(@sizeOf(TSS)) orelse unreachable;
        cpu_info[i].tss = @as(*TSS, @ptrCast(@alignCast(tss_mem)));
        cpu_info[i].tss.rsp0 = @intFromPtr(cpu_info[i].stack);
    }

    const cr3 = asm volatile (
        \\mov %%cr3, %[result]
        : [result] "=r" (-> usize),
    );

    const ap_boot_cr3_ptr: *u64 = @ptrFromInt(trampoline_addr + 0x18);

    ap_boot_cr3_ptr.* = cr3;
}

fn startAPs() void {
    for (1..num_cpus) |i| {
        startAP(@as(u32, @intCast(i)));

        var timeout: u32 = 10000000;
        while (!cpu_info[i].is_active and timeout > 0) : (timeout -= 1) {
            asm volatile ("pause");
        }

        if (cpu_info[i].is_active) {
            vga.print("CPU ");
            printNumber(@as(u32, @intCast(i)));
            vga.print(" started\n");
        }
    }
}

fn startAP(cpu_id: u32) void {
    const apic_id = cpu_info[cpu_id].apic_id;

    writeLocalAPIC(LOCAL_APIC_ICR_HIGH, apic_id << 24);
    writeLocalAPIC(LOCAL_APIC_ICR_LOW, 0x00C500);

    busyWait(10000);

    writeLocalAPIC(LOCAL_APIC_ICR_HIGH, apic_id << 24);
    writeLocalAPIC(LOCAL_APIC_ICR_LOW, 0x008500);

    busyWait(200);

    writeLocalAPIC(LOCAL_APIC_ICR_HIGH, apic_id << 24);
    writeLocalAPIC(LOCAL_APIC_ICR_LOW, 0x000608);

    busyWait(200);

    writeLocalAPIC(LOCAL_APIC_ICR_HIGH, apic_id << 24);
    writeLocalAPIC(LOCAL_APIC_ICR_LOW, 0x000608);
}

pub export fn ap_main(cpu_id: u32) void {
    cpu_info[cpu_id].is_active = true;
    enableLocalAPIC();

    cpus_started += 1;

    const process_mod = @import("../process/process.zig");

    const idle_proc = process_mod.create_kernel_process("idle-ap", apIdleTask);
    process_mod.setPerCPUCurrent(cpu_id, idle_proc);

    asm volatile ("sti");

    while (true) {
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

fn readIOAPIC(reg: u32) u32 {
    @as(*volatile u32, @ptrFromInt(ioapic_base + IOAPIC_REGSEL)).* = reg;
    return @as(*volatile u32, @ptrFromInt(ioapic_base + IOAPIC_REGWIN)).*;
}

fn writeIOAPIC(reg: u32, value: u32) void {
    @as(*volatile u32, @ptrFromInt(ioapic_base + IOAPIC_REGSEL)).* = reg;
    @as(*volatile u32, @ptrFromInt(ioapic_base + IOAPIC_REGWIN)).* = value;
}

fn rdmsr(msr: u32) u64 {
    // SAFETY: populated by the subsequent rdmsr instruction
    var low: u32 = undefined;
    // SAFETY: populated by the subsequent rdmsr instruction
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
    var i: u32 = 0;
    while (i < microseconds * 1000) : (i += 1) {
        asm volatile ("pause");
    }
}

fn printNumber(num: u32) void {
    if (num == 0) {
        vga.printChar('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[count] = @as(u8, @intCast('0' + (n % 10)));
        count += 1;
    }

    var i = count;
    while (i > 0) {
        i -= 1;
        vga.printChar(digits[i]);
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

    const apic_id = cpu_info[target_cpu].apic_id;
    writeLocalAPIC(LOCAL_APIC_ICR_HIGH, apic_id << 24);
    writeLocalAPIC(LOCAL_APIC_ICR_LOW, vector);
}

pub fn broadcastIPI(vector: u8) void {
    writeLocalAPIC(LOCAL_APIC_ICR_HIGH, 0);
    writeLocalAPIC(LOCAL_APIC_ICR_LOW, 0x000C0000 | vector);
}

pub fn endOfInterrupt() void {
    writeLocalAPIC(LOCAL_APIC_EOI, 0);
}

pub fn getNumCPUs() u32 {
    return num_cpus;
}

pub fn isSMPEnabled() bool {
    return smp_enabled;
}