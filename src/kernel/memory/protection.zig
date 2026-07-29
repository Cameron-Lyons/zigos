const std = @import("std");
const paging = @import("paging64.zig");
const vga = @import("../drivers/vga.zig");

// User-memory validation and user/kernel copies are owned by the native syscall
// surface (native/kernel_api/syscall_dispatch.validateUserRange), which checks
// each access against the calling task's registered address-space regions. The
// freestanding kernel only needs to lock down its own image here. The previous
// implementation walked 0xC0000000.. and re-mapped whatever it found writable;
// this kernel identity-maps the low 128 MiB, so that range held no mappings
// and nothing was ever protected.

const PAGE_SIZE: usize = 0x1000;

// Linker-script symbols bounding the region to write-protect: .multiboot,
// .text and .rodata (the measured region), then the embedded userspace ELF
// archive. The archive bytes are only ever read - the loader digests and
// copies them into freshly mapped frames - and keeping them immutable closes
// the window between digest verification and copy. The section that follows
// (.data) is 4 KiB aligned, so rounding the end up covers only linker
// padding.
extern const __kernel_measure_start: u8;
extern const __kernel_archive_end: u8;

pub fn protectKernelMemory() void {
    const image_start = @intFromPtr(&__kernel_measure_start);
    const image_end = @intFromPtr(&__kernel_archive_end);

    var addr = image_start & ~(PAGE_SIZE - 1);
    const rounded_image_end = std.math.add(usize, image_end, PAGE_SIZE - 1) catch
        @panic("kernel image protection extent overflows the native pager");
    const end = rounded_image_end & ~(PAGE_SIZE - 1);
    while (addr < end) : (addr += PAGE_SIZE) {
        paging.setPageReadOnly(addr);
    }
    // Without CR0.WP the read-only bits do not bind supervisor-mode writes
    // and the pass above would be decorative.
    paging.enableWriteProtect();

    vga.print("Kernel text, rodata, and userspace archive write-protected\n");
}
