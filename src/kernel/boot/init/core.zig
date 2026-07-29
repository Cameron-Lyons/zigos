const console = @import("../../utils/console.zig");
const isr = @import("../../interrupts/isr.zig");
const paging = @import("../../memory/paging64.zig");
const memory = @import("../../memory/memory.zig");

pub fn init() void {
    // Paint the free boot stack first, while the call chain is shallow, so
    // the high-water mark reported at NATIVE:READY covers all of boot.
    const stack_watermark = @import("../../utils/stack_watermark.zig");
    stack_watermark.paint();

    console.print("Initializing GDT...\n");
    const gdt = @import("../../interrupts/gdt64.zig");
    gdt.init();
    console.print("GDT initialized!\n");

    console.print("Initializing interrupts...\n");
    isr.init();
    console.print("Interrupts enabled!\n");

    console.print("Initializing paging...\n");
    paging.init();
    @import("../common.zig").printBootMarker(@import("../markers.zig").x86_64_paging_ready);

    console.print("Enabling kernel memory protection...\n");
    const protection = @import("../../memory/protection.zig");
    protection.protectKernelMemory();
    @import("../common.zig").printBootMarker(@import("../markers.zig").kernel_wx_enforced);

    console.print("Initializing memory allocator...\n");
    memory.init();

    console.print("Initializing environment variables...\n");
    const environ = @import("../../utils/environ.zig");
    environ.init();
}
