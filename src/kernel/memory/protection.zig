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

extern const __kernel_text_start: u8;
extern const __kernel_text_end: u8;
extern const __kernel_rodata_start: u8;
extern const __kernel_rodata_end: u8;
extern const __kernel_archive_start: u8;
extern const __kernel_archive_end: u8;
extern const __kernel_relro_start: u8;
extern const __kernel_relro_end: u8;
extern const __kernel_data_start: u8;
extern const __kernel_data_end: u8;
extern const __kernel_bss_start: u8;
extern const __kernel_bss_end: u8;
extern var stack_bottom: u8;

const PageRange = struct {
    start: usize,
    end: usize,
};

fn linkerRange(start_symbol: *const u8, end_symbol: *const u8) PageRange {
    const start = @intFromPtr(start_symbol);
    const end = @intFromPtr(end_symbol);
    if (start % PAGE_SIZE != 0 or end % PAGE_SIZE != 0 or start > end) {
        @panic("invalid page-aligned kernel section extent");
    }
    return .{ .start = start, .end = end };
}

fn nonEmptyLinkerRange(start_symbol: *const u8, end_symbol: *const u8) PageRange {
    const range = linkerRange(start_symbol, end_symbol);
    if (range.start == range.end) @panic("required kernel section is empty");
    return range;
}

fn setRangeReadOnly(range: PageRange) void {
    var addr = range.start;
    while (addr < range.end) : (addr += PAGE_SIZE) {
        paging.setPageReadOnly(addr);
    }
}

fn verifyRange(
    range: PageRange,
    writable: bool,
    executable: bool,
    allowed_unmapped_page: ?usize,
) void {
    var addr = range.start;
    while (addr < range.end) : (addr += PAGE_SIZE) {
        const permissions = paging.currentPagePermissions(addr) orelse {
            if (allowed_unmapped_page != null and addr == allowed_unmapped_page.?) continue;
            @panic("kernel section page is unexpectedly unmapped");
        };
        if (permissions.user or
            permissions.writable != writable or
            permissions.executable != executable)
        {
            @panic("kernel section page permissions violate W^X");
        }
    }
}

pub fn protectKernelMemory() void {
    const text = nonEmptyLinkerRange(&__kernel_text_start, &__kernel_text_end);
    const rodata = nonEmptyLinkerRange(&__kernel_rodata_start, &__kernel_rodata_end);
    const archive = nonEmptyLinkerRange(&__kernel_archive_start, &__kernel_archive_end);
    const relro = linkerRange(&__kernel_relro_start, &__kernel_relro_end);
    const data = nonEmptyLinkerRange(&__kernel_data_start, &__kernel_data_end);
    const bss = nonEmptyLinkerRange(&__kernel_bss_start, &__kernel_bss_end);

    // The userspace archive is immutable after link: launch verifies its digest
    // before copying bytes into task-owned frames. Keeping it R/NX closes the
    // verification-to-copy window just like ordinary kernel rodata.
    setRangeReadOnly(text);
    setRangeReadOnly(rodata);
    setRangeReadOnly(archive);
    setRangeReadOnly(relro);

    // Without CR0.WP the read-only bits do not bind supervisor writes.
    paging.enableWriteProtect();

    verifyRange(text, false, true, null);
    verifyRange(rodata, false, false, null);
    verifyRange(archive, false, false, null);
    verifyRange(relro, false, false, null);
    verifyRange(data, true, false, null);
    verifyRange(bss, true, false, @intFromPtr(&stack_bottom));

    vga.print("Kernel W^X enforced: text RX, immutable data R/NX, mutable memory RW/NX\n");
}
