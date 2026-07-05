const paging = @import("paging.zig");
const vga = @import("../drivers/vga.zig");

// User-memory validation and user/kernel copies are owned by the native syscall
// surface (native/kernel_api/syscall_dispatch.validateUserRange), which checks
// each access against the calling task's registered address-space regions. The
// freestanding kernel only needs to lock down its own image here. The previous
// implementation walked 0xC0000000.. and re-mapped whatever it found writable;
// this kernel identity-maps the low 128 MiB, so that range held no mappings
// and nothing was ever protected.

const PAGE_SIZE_U32: u32 = 0x1000;

// Linker-script symbols bounding the measured region: .multiboot, .text and
// .rodata. The section that follows (.zigos_userspace_archive) is 4 KiB
// aligned, so rounding the end up covers only linker padding.
extern const __kernel_measure_start: u8;
extern const __kernel_measure_end: u8;

pub fn protectKernelMemory() void {
    const image_start: u32 = @intFromPtr(&__kernel_measure_start);
    const image_end: u32 = @intFromPtr(&__kernel_measure_end);

    var addr = image_start & ~(PAGE_SIZE_U32 - 1);
    const end = (image_end + PAGE_SIZE_U32 - 1) & ~(PAGE_SIZE_U32 - 1);
    while (addr < end) : (addr += PAGE_SIZE_U32) {
        paging.setPageReadOnly(addr);
    }
    // Without CR0.WP the read-only bits do not bind supervisor-mode writes
    // and the pass above would be decorative.
    paging.enableWriteProtect();

    vga.print("Kernel text and rodata write-protected\n");
}
