const console = @import("../../utils/console.zig");
const isr = @import("../../interrupts/isr.zig");
const paging = @import("../../memory/paging.zig");
const swap = @import("../../memory/swap.zig");
const memory = @import("../../memory/memory.zig");

pub fn init() void {
    console.print("Initializing GDT...\n");
    const gdt = @import("../../interrupts/gdt.zig");
    gdt.init();
    console.print("GDT initialized!\n");

    console.print("Initializing interrupts...\n");
    isr.init();
    console.print("Interrupts enabled!\n");

    console.print("Initializing paging...\n");
    paging.init();

    console.print("Initializing swap...\n");
    swap.init();

    console.print("Enabling kernel memory protection...\n");
    const protection = @import("../../memory/protection.zig");
    protection.protectKernelMemory();

    console.print("Initializing memory allocator...\n");
    memory.init();

    console.print("Initializing environment variables...\n");
    const environ = @import("../../utils/environ.zig");
    environ.init();
}
