const paging = @import("paging.zig");
const vga = @import("../drivers/vga.zig");

// User-memory validation and user/kernel copies are owned by the native syscall
// surface (native/kernel_api/syscall_dispatch.validateUserRange), which checks
// each access against the calling task's registered address-space regions. The
// freestanding kernel only needs to lock down its own mapping range here.

const KERNEL_BASE: u32 = 0xC0000000;
const PAGE_SIZE_U32: u32 = 0x1000;
const KERNEL_PROTECTION_END: u32 = 0xFFFF_FFFF;
const LAST_KERNEL_PAGE_START: u32 = 0xFFFF_F000;

pub fn protectKernelMemory() void {
    var addr: u32 = KERNEL_BASE;
    while (addr < KERNEL_PROTECTION_END) : (addr += PAGE_SIZE_U32) {
        if (paging.get_physical_address(addr)) |phys| {
            paging.mapPage(addr, phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
        }

        if (addr == LAST_KERNEL_PAGE_START) break;
    }

    vga.print("Kernel memory protected\n");
}
