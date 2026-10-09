// Shared boot-only support for isolated cache-admission guest evidence.
// No AP runs generated code until the production transition admits it.
const x86 = @import("../x86.zig");
const features = @import("../cpu_features.zig");
const identity = @import("../../kernel/cpu_identity.zig");
const memory = @import("../../kernel/memory/memory.zig");
const paging = @import("../../kernel/memory/paging64.zig");
const gdt = @import("../../kernel/interrupts/gdt64.zig");
const idt = @import("../../kernel/interrupts/idt64.zig");
const x2apic = @import("../../kernel/interrupts/x2apic.zig");
const bridge = @import("../../kernel/smp/trampoline.zig");
const clock = @import("../../kernel/timer/tsc_clock.zig");

pub const SipiPage = struct { physical: u32, bytes: []align(4096) u8 };
const PAGE_BYTES: usize = 4096;
const AP_ID: u32 = 1;
// The host pins this emulator clock; it is not hardware frequency admission.
const PROOF_TSC_FREQUENCY_HZ: u64 = 2_400_000_000;
extern var stack_top: u8;

pub fn initializeBsp() void {
    @import("../../kernel/utils/console.zig").init();
    if (x86.interruptsEnabled()) fail("BSP_INTERRUPTS");
    features.initializeNativeCachePolicy() catch fail("BSP_CACHE_ADMISSION");
    identity.initialize(0);
    const emergency = memory.claimEarly(gdt.DOUBLE_FAULT_STACK_STORAGE_BYTES, gdt.DOUBLE_FAULT_STACK_ALIGNMENT) orelse fail("BSP_EMERGENCY_STACK");
    if (!gdt.bindDoubleFaultStacks(emergency)) fail("BSP_EMERGENCY_BINDING");
    gdt.init();
    gdt.setKernelStack(@intFromPtr(&stack_top));
    idt.init();
    paging.init();
    if (!paging.kernelAddressSpaceActive()) fail("BSP_FINAL_ROOT");
    memory.init();
    clock.init(PROOF_TSC_FREQUENCY_HZ);
    if (!features.detect().x2apic) fail("BSP_X2APIC");
    x2apic.enable();
    if (x2apic.localId() != 0) fail("BSP_TOPOLOGY");
    x86.outb(0x21, 0xff);
    x86.outb(0xa1, 0xff);
    const max_lvt: u8 = @truncate(x86.readMsr(0x803) >> 16);
    if (max_lvt < 5) fail("BSP_LVT_BOUND");
    inline for ([_]u32{ 0x832, 0x833, 0x834, 0x835, 0x836, 0x837 }) |msr|
        x86.writeMsr(msr, x86.readMsr(msr) | (1 << 16));
    if (max_lvt >= 6) x86.writeMsr(0x82f, x86.readMsr(0x82f) | (1 << 16));
}

pub fn claimPage() SipiPage {
    const physical = paging.claimSipiTrampolinePage() orelse fail("SIPI_RESERVATION");
    if (physical == 0 or physical >= bridge.PHYSICAL_LIMIT or physical % PAGE_BYTES != 0) fail("SIPI_PHYSICAL_RANGE");
    const alias = paging.directMapAddress(physical) orelse fail("SIPI_ALIAS");
    const bytes: [*]align(PAGE_BYTES) u8 = @ptrFromInt(alias);
    return .{ .physical = physical, .bytes = bytes[0..PAGE_BYTES] };
}

pub fn publish(page: SipiPage) void {
    const line_bytes = features.clflushLineBytes() orelse fail("SIPI_FLUSH_STRIDE");
    if (page.bytes.len != PAGE_BYTES or @intFromPtr(page.bytes.ptr) % PAGE_BYTES != 0 or
        paging.directMapAddress(page.physical) != @intFromPtr(page.bytes.ptr)) fail("SIPI_PUBLICATION_RANGE");
    var offset: usize = 0;
    while (offset < PAGE_BYTES) : (offset += line_bytes) x86.flushCacheLine(@intFromPtr(page.bytes.ptr) + offset);
    asm volatile ("mfence" ::: .{ .memory = true });
}

pub fn prepareBridge(entry: *const fn (u64) callconv(.c) noreturn) bridge.Trampoline {
    const trampoline = bridge.install() orelse fail("SIPI_BRIDGE_INSTALL");
    paging.mapKernelBorrowedPage(trampoline.physical, trampoline.physical, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_EXECUTABLE);
    const stack = bridge.allocateStack() orelse fail("SIPI_HIGH_STACK");
    if (!bridge.patch(trampoline, 1, stack.top, entry)) fail("SIPI_BRIDGE_PATCH");
    // Keep the page, stack and root until emulator termination, even on failure.
    return trampoline;
}

pub fn prepareAp() void {
    if (x86.interruptsEnabled()) fail("LAUNCH_INTERRUPTS");
    x2apic.sendInit(AP_ID);
    waitMilliseconds(10);
}

pub fn launchPhysical(physical: u32) void {
    if (physical == 0 or physical >= bridge.PHYSICAL_LIMIT or physical % PAGE_BYTES != 0) fail("SIPI_VECTOR");
    x2apic.sendStartup(AP_ID, @intCast(physical / PAGE_BYTES));
}

pub fn startAp(page: SipiPage, status: *u32) void {
    prepareAp();
    launchPhysical(page.physical);
    waitMilliseconds(1);
    // A repeated SIPI does not reset a running AP. There is no subsequent INIT
    // or patch between the two callable macro invocations.
    if (@atomicLoad(u32, status, .acquire) == 0) launchPhysical(page.physical);
}

pub fn waitForPhase(status: *u32, wanted: u32) void {
    if (wanted != 1 and wanted != 2) fail("INVALID_PHASE");
    const deadline = clock.afterMilliseconds(2000);
    while (true) {
        const observed = @atomicLoad(u32, status, .acquire);
        if (observed > 2) fail("AP_PHASE_REJECTED");
        if (observed >= wanted) return;
        if (deadline.expired()) fail("AP_PHASE_TIMEOUT");
        asm volatile ("pause");
    }
}

fn waitMilliseconds(milliseconds: u64) void {
    const deadline = clock.afterMilliseconds(milliseconds);
    while (!deadline.expired()) asm volatile ("pause");
}

pub fn serialWrite(bytes: []const u8) void {
    for (bytes) |byte| {
        for (0..100_000) |_| {
            if (x86.inb(0x3fd) & 0x20 != 0) break;
            asm volatile ("pause");
        }
        x86.outb(0x3f8, byte);
    }
}

pub fn pass(comptime stage: []const u8) void {
    serialWrite("ZIGOS:ARCH:X86_64:AP_CACHE:" ++ stage ++ ":PASS\n");
}

pub fn fail(comptime reason: []const u8) noreturn {
    serialWrite("ZIGOS:ARCH:X86_64:AP_CACHE:FAIL:" ++ reason ++ "\n");
    x86.outl(0xf4, 0x11);
    retainAndHalt();
}

pub fn finish() noreturn {
    x86.outl(0xf4, 0x10);
    retainAndHalt();
}

pub fn retainAndHalt() noreturn {
    x86.cli();
    while (true) x86.hlt();
}
