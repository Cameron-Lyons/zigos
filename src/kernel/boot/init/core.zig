const console = @import("../../utils/console.zig");
const isr = @import("../../interrupts/isr.zig");
const paging = @import("../../memory/paging64.zig");
const memory = @import("../../memory/memory.zig");
const userspace_executor = @import("../../../native/task/userspace_executor.zig");

pub fn init() void {
    const stack_watermark = @import("../../utils/stack_watermark.zig");
    stack_watermark.paint();

    console.print("Initializing GDT...\n");
    const gdt = @import("../../interrupts/gdt64.zig");
    const double_fault_stack_memory = memory.claimEarly(
        gdt.DOUBLE_FAULT_STACK_TOTAL_BYTES,
        gdt.DOUBLE_FAULT_STACK_ALIGNMENT,
    ) orelse @panic("insufficient early heap for double-fault stack");
    if (!gdt.bindDoubleFaultStack(double_fault_stack_memory)) @panic("double-fault stack already bound");
    gdt.init();
    console.print("GDT initialized!\n");

    console.print("Initializing native syscall entry...\n");
    const syscall64 = @import("../../interrupts/syscall64.zig");
    syscall64.init();
    console.print("Native syscall entry initialized!\n");

    console.print("Initializing interrupts...\n");
    isr.init();
    console.print("Interrupts enabled!\n");

    console.print("Initializing paging...\n");
    paging.init();
    if (!paging.unmapBorrowedCurrentPage(gdt.doubleFaultStackGuardAddress())) {
        @panic("failed to arm double-fault stack guard");
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
