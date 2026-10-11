const console = @import("../../utils/console.zig");
const isr = @import("../../interrupts/isr.zig");
const paging = @import("../../memory/paging64.zig");
const memory = @import("../../memory/memory.zig");
const userspace_executor = @import("../../../native/task/userspace_executor.zig");

pub fn init(lass_supported: bool) error{UnsupportedKernelAddressPartition}!void {
    const stack_watermark = @import("../../utils/stack_watermark.zig");
    stack_watermark.paint();

    console.print("Initializing GDT...\n");
    const gdt = @import("../../interrupts/gdt64.zig");
    const double_fault_stack_memory = memory.claimEarly(
        gdt.DOUBLE_FAULT_STACK_STORAGE_BYTES,
        gdt.DOUBLE_FAULT_STACK_ALIGNMENT,
    ) orelse @panic("insufficient early heap for double-fault stack");
    if (!gdt.bindDoubleFaultStacks(double_fault_stack_memory)) @panic("double-fault stacks already bound");
    gdt.init();
    console.print("GDT initialized!\n");

    console.print("Initializing native syscall entry...\n");
    const syscall64 = @import("../../interrupts/syscall64.zig");
    syscall64.init();
    console.print("Native syscall entry initialized!\n");

    console.print("Initializing interrupts...\n");
    isr.init();
    console.print("Interrupt descriptors initialized!\n");

    if (lass_supported) {
        const x86 = @import("../../../arch/x86.zig");
        try x86.enableLass();
        if (!x86.lassEnabled()) unreachable;
    }

    console.print("Initializing paging...\n");
    paging.init();
    for (0..@import("../../cpu_identity.zig").MAX_CPUS) |index| {
        if (!paging.unmapBorrowedCurrentPage(gdt.doubleFaultStackGuardAddressForCpu(@intCast(index)))) {
            @panic("failed to arm double-fault stack guard");
        }
    }
    @import("../common.zig").printBootMarker(@import("../markers.zig").x86_64_paging_ready);

    console.print("Enabling kernel memory protection...\n");
    const protection = @import("../../memory/protection.zig");
    protection.protectKernelMemory();
    @import("../common.zig").printBootMarker(@import("../markers.zig").kernel_wx_enforced);

    userspace_executor.reserveTrapStackStorage() catch @panic("insufficient early heap for userspace trap stack");

    console.print("Initializing memory allocator...\n");
    memory.init();
}
