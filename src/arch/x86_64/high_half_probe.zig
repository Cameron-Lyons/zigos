const std = @import("std");
const x86 = @import("../x86.zig");
const address = @import("../kernel_address.zig");
const paging = @import("../../kernel/memory/paging64.zig");
const memory = @import("../../kernel/memory/memory.zig");
const handoff = @import("../../kernel/boot/handoff.zig");
const gdt = @import("../../kernel/interrupts/gdt64.zig");
const idt = @import("../../kernel/interrupts/idt64.zig");
const cpu_identity = @import("../../kernel/cpu_identity.zig");

const SERIAL_BASE: u16 = 0x3F8;
const QEMU_EXIT_PORT: u16 = 0xF4;
const INITIAL_ANCHOR: u64 = 0x7468_6769_682d_736f;

var image_anchor: u64 = INITIAL_ANCHOR;

extern var __kernel_start: u8;
extern var __kernel_end: u8;
extern var stack_bottom: u8;
extern var stack_top: u8;

pub fn panic(_: []const u8, _: ?*std.lang.StackTrace, _: ?usize) noreturn {
    fail("panic");
}

pub export fn kernel_main() callconv(.c) noreturn {
    @import("../../kernel/utils/console.zig").init();
    if (comptime @import("mapping_xstate_probe.zig").enabled) @import("mapping_xstate_probe.zig").preflightBsp();
    @import("../cpu_features.zig").initializeNativeCachePolicy() catch fail("cache policy admission");
    const instruction = asm volatile ("lea 0(%%rip), %[value]"
        : [value] "=r" (-> usize),
    );
    const image_start = @intFromPtr(&__kernel_start);
    const image_end = @intFromPtr(&__kernel_end);
    if (image_start != address.image_virtual_bias + 32 * 1024 * 1024 or
        instruction < image_start or instruction >= image_end) fail("entry");
    pass("ENTRY");

    const stack = x86.stackPointer();
    if (stack < @intFromPtr(&stack_bottom) or stack >= @intFromPtr(&stack_top) or
        address.imagePhysicalAddress(stack) == null) fail("stack");
    pass("STACK");

    const anchor_address = @intFromPtr(&image_anchor);
    const anchor_physical = address.imagePhysicalAddress(anchor_address) orelse fail("image LMA");
    if (address.imagePhysicalAddress(image_start).? != 32 * 1024 * 1024 or
        anchor_physical < 32 * 1024 * 1024 or handoff.zigos_multiboot_magic != 0x36D7_6289 or
        handoff.zigos_multiboot_info_addr == 0) fail("image LMA");
    pass("IMAGE_LMA");

    // Exercise a compiled static pointer and the independent physical alias.
    // Volatile accesses prevent the optimizer from replacing either read.
    const anchor: *volatile u64 = &image_anchor;
    const direct: *volatile u64 = @ptrFromInt(address.directMappedAddress(anchor_physical, address.image_physical_limit).?);
    if (anchor.* != INITIAL_ANCHOR or direct.* != INITIAL_ANCHOR) fail("direct map");
    direct.* ^= 1;
    if (anchor.* != (INITIAL_ANCHOR ^ 1)) fail("direct map write");
    anchor.* = INITIAL_ANCHOR;
    if (direct.* != INITIAL_ANCHOR) fail("direct map restore");
    pass("DIRECT_MAP");

    const cr3_physical = x86.readCr3() & x86.CR3_ADDRESS_MASK;
    if (x86.readCr0() & x86.CR0_WP == 0 or x86.readMsr(x86.EFER_MSR) & x86.EFER_NXE == 0) fail("bootstrap NX/WP controls");
    if (cr3_physical == 0 or cr3_physical % 4096 != 0 or cr3_physical >= address.image_physical_limit) fail("CR3");
    const pml4: [*]volatile u64 = @ptrFromInt(address.directMappedAddress(cr3_physical, address.image_physical_limit).?);
    if (pml4[511] & 5 != 1 or pml4[256] & 5 != 1) fail("supervisor roots");
    pass("CR3");
    @import("high_half_smp_probe.zig").proveBootArenaSizing(cr3_physical);

    var x87_control: u16 = undefined;
    var mxcsr: u32 = undefined;
    asm volatile ("fnstcw %[control]"
        : [control] "=m" (x87_control),
    );
    asm volatile ("stmxcsr %[control]"
        : [control] "=m" (mxcsr),
    );
    if (x87_control != 0x037F or mxcsr != 0x1F80) fail("FP controls");
    pass("FP_CONTROLS");

    if (!@import("../cpu_features.zig").detect().smap) fail("SMAP support");
    x86.writeCr4(x86.readCr4() | x86.CR4_SMAP);
    if (!x86.supervisorAccessPreventionEnabled()) fail("SMAP enabled");
    x86.allowSupervisorUserMemory();
    if (!alignmentCheckEnabled()) fail("SMAP AC set");
    x86.forbidSupervisorUserMemory();
    if (alignmentCheckEnabled()) fail("SMAP AC clear");
    pass("SMAP_AC");

    x86.enableNoExecute();
    cpu_identity.initialize(0);
    const emergency_stacks = memory.claimEarly(gdt.DOUBLE_FAULT_STACK_STORAGE_BYTES, gdt.DOUBLE_FAULT_STACK_ALIGNMENT) orelse fail("emergency stack storage");
    if (!gdt.bindDoubleFaultStacks(emergency_stacks)) fail("emergency stack binding");
    gdt.init();
    gdt.setKernelStack(@intFromPtr(&stack_top));
    idt.init();
    if (!x86.lassAddressPartitionSupported()) fail("descriptor address partition");
    pass("DESCRIPTORS");
    paging.init();
    const final_cr3 = x86.readCr3() & x86.CR3_ADDRESS_MASK;
    if (final_cr3 == cr3_physical or !paging.kernelAddressSpaceActive()) fail("final CR3");
    const final_root: [*]volatile u64 = @ptrFromInt(paging.directMapAddress(final_cr3).?);
    for (0..256) |index| if (final_root[index] != 0) fail("kernel lower aliases");
    pass("FINAL_CR3");
    @import("high_half_smp_probe.zig").proveBootArenaReclamation(final_cr3, instruction, anchor_address);

    expectPermissions(instruction, false, true);
    expectPermissions(paging.directMapAddress(address.imagePhysicalAddress(instruction).?).?, false, false);
    expectPermissions(anchor_address, true, false);
    if (paging.currentPagePermissions(@intFromPtr(&stack_bottom)) != null) fail("boot stack guard");
    for (0..cpu_identity.MAX_CPUS) |index| {
        const guard = gdt.doubleFaultStackGuardAddressForCpu(@intCast(index));
        if (!paging.unmapBorrowedCurrentPage(guard) or paging.currentPagePermissions(guard) != null) fail("emergency stack guard");
        expectPermissions(guard + 4096, true, false);
    }
    pass("W_X");

    const guard_memory = memory.claimEarly(8192, 4096) orelse fail("heap guard storage");
    const guard_address = @intFromPtr(guard_memory);
    expectPermissions(guard_address, true, false);
    expectPermissions(guard_address + 4096, true, false);
    if (!paging.unmapBorrowedCurrentPage(guard_address) or
        paging.currentPagePermissions(guard_address) != null) fail("4K heap guard");
    memory.init();
    const allocation = memory.kmalloc(256) orelse fail("high heap allocation");
    const allocation_address = @intFromPtr(allocation);
    if (address.directMappedPhysicalAddress(allocation_address, address.direct_map_capacity) == null) fail("high heap address");
    expectPermissions(allocation_address, true, false);
    const payload: *volatile u64 = @ptrCast(@alignCast(allocation));
    payload.* = INITIAL_ANCHOR;
    if (payload.* != INITIAL_ANCHOR) fail("high heap write");
    pass("HEAP_GUARD");

    var space = paging.createUserAddressSpace() catch fail("user root allocation");
    for (space.directory[0..256]) |entry| if (entry != 0) fail("user lower aliases");
    if (space.directory[511] != final_root[511] or space.directory[256] != final_root[256]) fail("user upper inheritance");
    paging.switchToUserAddressSpace(&space);
    if (x86.readCr3() & x86.CR3_ADDRESS_MASK == final_cr3 or
        paging.currentPagePermissions(32 * 1024 * 1024) != null) fail("user root switch");
    expectPermissions(instruction, false, true);
    expectPermissions(allocation_address, true, false);
    if (payload.* != INITIAL_ANCHOR) fail("inherited heap payload");
    paging.switchToKernelAddressSpace();
    if (x86.readCr3() & x86.CR3_ADDRESS_MASK != final_cr3) fail("kernel root restore");
    paging.destroyUserAddressSpace(&space) catch fail("user root reclamation");
    memory.kfree(allocation);
    if (!x86.supervisorAccessPreventionEnabled() or alignmentCheckEnabled()) fail("SMAP continuation");
    pass("USER_ROOT");
    @import("high_half_shared_probe.zig").run();
    @import("high_half_smp_probe.zig").run();
    serialWrite("ZIGOS:ARCH:X86_64:HIGH_HALF:PASS\n");
    exitQemu(0x10);
}

pub fn pass(comptime label: []const u8) void {
    serialWrite("ZIGOS:ARCH:X86_64:HIGH_HALF:" ++ label ++ ":PASS\n");
}

pub fn fail(comptime reason: []const u8) noreturn {
    serialWrite("ZIGOS:ARCH:X86_64:HIGH_HALF:FAIL " ++ reason ++ "\n");
    exitQemu(0x11);
}

fn expectPermissions(virtual_address: usize, writable: bool, executable: bool) void {
    const permissions = paging.currentPagePermissions(virtual_address) orelse fail("missing page");
    if (permissions.user or permissions.writable != writable or permissions.executable != executable) fail("page permissions");
}

fn alignmentCheckEnabled() bool {
    const flags = asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> usize),
    );
    return flags & (1 << 18) != 0;
}

fn serialWrite(bytes: []const u8) void {
    for (bytes) |byte| {
        while (x86.inb(SERIAL_BASE + 5) & 0x20 == 0) asm volatile ("pause");
        x86.outb(SERIAL_BASE, byte);
    }
}

fn exitQemu(value: u32) noreturn {
    x86.outl(QEMU_EXIT_PORT, value);
    while (true) x86.hlt();
}
