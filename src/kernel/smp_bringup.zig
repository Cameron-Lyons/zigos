const smp = @import("smp.zig");
const x2apic = @import("interrupts/x2apic.zig");
const x86 = @import("../arch/x86.zig");
const tsc_clock = @import("timer/tsc_clock.zig");
const spin = @import("utils/spin.zig");
const paging = @import("memory/paging64.zig");
const gdt = @import("interrupts/gdt64.zig");
const idt = @import("interrupts/idt64.zig");
const kernel_memory = @import("root").kernel_memory;

extern var smp_trampoline_start: u8;
extern var smp_trampoline_end: u8;
extern var smp_trampoline_cr3: u64;
extern var smp_trampoline_cr4: u64;
extern var smp_trampoline_efer: u64;
extern var smp_trampoline_entry: u64;
extern var smp_trampoline_stack: u64;
extern var smp_trampoline_cpu: u64;

const INIT_HOLD_MILLISECONDS: u64 = 10;
const STARTUP_HOLD_MILLISECONDS: u64 = 1;
const AP_ONLINE_MILLISECONDS: u64 = 100;

var bringup_cpus: *[smp.MAX_CPUS]smp.Cpu = undefined;
var bringup_cpu_count: *u8 = undefined;
var bringup_online_count: *u8 = undefined;

pub fn start(cpus: *[smp.MAX_CPUS]smp.Cpu, cpu_count: *u8, online_count: *u8) void {
    bringup_cpus = cpus;
    bringup_cpu_count = cpu_count;
    bringup_online_count = online_count;
    paging.setRemotePcidShootdown(smp.shootdownPcid);
    if (cpu_count.* <= 1) return;
    const trampoline = installTrampoline() orelse return;
    var index: u8 = 1;
    while (index < cpu_count.*) : (index += 1) {
        startOne(index, trampoline);
    }
}

const Trampoline = struct {
    physical: u32,
    bytes: []u8,
};

fn installTrampoline() ?Trampoline {
    const physical = paging.claimSipiTrampolinePage() orelse return null;
    if (physical == 0 or physical >= smp.SIPI_PHYSICAL_LIMIT or physical % 4096 != 0) return null;
    const start_addr = @intFromPtr(&smp_trampoline_start);
    const end_addr = @intFromPtr(&smp_trampoline_end);
    if (end_addr <= start_addr or end_addr - start_addr > 4096) return null;
    const dest: [*]u8 = @ptrFromInt(physical);
    const bytes = dest[0..(end_addr - start_addr)];
    @memcpy(bytes, @as([*]const u8, @ptrFromInt(start_addr))[0 .. end_addr - start_addr]);
    return .{ .physical = physical, .bytes = bytes };
}

fn patch(bytes: []u8, cpu_index: u8, stack_top: u64) void {
    writeU64(bytes, &smp_trampoline_cr3, x86.readCr3() & x86.CR3_ADDRESS_MASK);
    writeU64(bytes, &smp_trampoline_cr4, x86.readCr4());
    writeU64(bytes, &smp_trampoline_efer, x86.readMsr(x86.EFER_MSR));
    writeU64(bytes, &smp_trampoline_entry, @intFromPtr(&apEntry));
    writeU64(bytes, &smp_trampoline_stack, stack_top);
    writeU64(bytes, &smp_trampoline_cpu, cpu_index);
}

fn writeU64(bytes: []u8, symbol: *u64, value: u64) void {
    const offset = @intFromPtr(symbol) - @intFromPtr(&smp_trampoline_start);
    const std = @import("std");
    std.mem.writeInt(u64, bytes[offset..][0..8], value, .little);
}

fn startOne(index: u8, trampoline: Trampoline) void {
    const stack = kernel_memory.kmalloc(smp.AP_STACK_BYTES) orelse return;
    const stack_bytes: [*]u8 = @ptrCast(stack);
    const stack_top = @intFromPtr(stack_bytes) + smp.AP_STACK_BYTES;
    patch(trampoline.bytes, index, stack_top);

    const apic_id = bringup_cpus[index].apic_id;
    const vector: u8 = @intCast(trampoline.physical / 4096);
    x2apic.sendInit(apic_id);
    waitMilliseconds(INIT_HOLD_MILLISECONDS);
    x2apic.sendStartup(apic_id, vector);
    waitMilliseconds(STARTUP_HOLD_MILLISECONDS);
    if (!bringup_cpus[index].online) {
        x2apic.sendStartup(apic_id, vector);
        waitMilliseconds(STARTUP_HOLD_MILLISECONDS);
    }

    const deadline = tsc_clock.afterMilliseconds(AP_ONLINE_MILLISECONDS);
    while (!bringup_cpus[index].online) {
        if (deadline.expired()) return;
        spin.hint();
    }
}

fn waitMilliseconds(milliseconds: u64) void {
    const deadline = tsc_clock.afterMilliseconds(milliseconds);
    while (!deadline.expired()) spin.hint();
}

fn apEntry(cpu_index: u64) callconv(.c) noreturn {
    const index: u8 = @truncate(cpu_index);
    x86.enableSse();
    x86.enableXsaves();
    x86.enableCetOnApplicationProcessor();
    gdt.loadCurrent();
    idt.init();
    x2apic.enable();
    smp.setCurrentCpuIndex(index);
    bringup_cpus[index].online = true;
    bringup_online_count.* += 1;
    while (true) smp.idle();
}
