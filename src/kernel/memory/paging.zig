const vga = @import("../drivers/vga.zig");
const memory = @import("memory.zig");
const numfmt = @import("../utils/numfmt.zig");

const PAGE_SIZE = 4096;
const PAGE_SHIFT = 12;
const PAGES_PER_TABLE = 1024;
const TABLES_PER_DIRECTORY = 1024;
const PAGE_DIRECTORY_SHIFT = 22;
const PAGE_TABLE_INDEX_MASK: u32 = PAGES_PER_TABLE - 1;
const PAGE_OFFSET_MASK: u32 = PAGE_SIZE - 1;
const FRAME_BITMAP_WORD_BITS = 32;
const HEX_NIBBLE_BITS = 4;
const HEX_HIGH_NIBBLE_SHIFT: u32 = 28;
const HEX_NIBBLE_MASK: u32 = 0xF;

pub const PAGE_PRESENT: u32 = 0x1;
pub const PAGE_WRITABLE: u32 = 0x2;
pub const PAGE_USER: u32 = 0x4;
pub const PAGE_WRITE_THROUGH: u32 = 0x8;
pub const PAGE_CACHE_DISABLE: u32 = 0x10;
pub const PAGE_ACCESSED: u32 = 0x20;
pub const PAGE_DIRTY: u32 = 0x40;
pub const PAGE_GLOBAL: u32 = 0x100;

pub const PageTableEntry = packed struct {
    present: bool = false,
    writable: bool = false,
    user: bool = false,
    write_through: bool = false,
    cache_disabled: bool = false,
    accessed: bool = false,
    dirty: bool = false,
    page_size: bool = false,
    global: bool = false,
    available: u3 = 0,
    address: u20 = 0,
};

pub const PageTable = [PAGES_PER_TABLE]PageTableEntry;
pub const PageDirectory = [TABLES_PER_DIRECTORY]PageTableEntry;

const MEMORY_SIZE = 128 * 1024 * 1024;
const IDENTITY_MAPPED_TABLES = MEMORY_SIZE / (PAGE_SIZE * PAGES_PER_TABLE);

// Lowest address of the BSP boot stack, page-aligned in boot64.S. The stack
// grows down toward the kernel globals placed just below it in .bss.
extern var stack_bottom: u8;

// SAFETY: fully initialized in init() which identity-maps the first 128MB
var kernel_page_directory: PageDirectory align(PAGE_SIZE) = undefined;
// SAFETY: fully initialized in init() which identity-maps the first 128MB
var kernel_page_tables: [IDENTITY_MAPPED_TABLES]PageTable align(PAGE_SIZE) = undefined;

const FRAME_COUNT = MEMORY_SIZE / PAGE_SIZE;
const BITMAP_SIZE = FRAME_COUNT / FRAME_BITMAP_WORD_BITS;

// SAFETY: zeroed and populated in init() before any frame allocation
var frame_bitmap: [BITMAP_SIZE]u32 = undefined;
var total_frames: u32 = FRAME_COUNT;
var used_frames: u32 = 0;
var frame_lock: bool = false;
var frame_search_word_hint: u32 = 0;

fn set_frame(frame_addr: u32) void {
    const frame = frame_addr / PAGE_SIZE;
    const idx = frame / FRAME_BITMAP_WORD_BITS;
    const offset = frame % FRAME_BITMAP_WORD_BITS;
    const mask = @as(u32, 1) << @truncate(offset);
    if ((frame_bitmap[idx] & mask) == 0) {
        frame_bitmap[idx] |= mask;
        used_frames += 1;
    }
}

fn test_frame(frame_addr: u32) bool {
    const frame = frame_addr / PAGE_SIZE;
    const idx = frame / FRAME_BITMAP_WORD_BITS;
    const offset = frame % FRAME_BITMAP_WORD_BITS;
    return (frame_bitmap[idx] & (@as(u32, 1) << @truncate(offset))) != 0;
}

fn find_free_frame_range(start_word: u32, end_word: u32) ?u32 {
    var i = start_word;
    while (i < end_word) : (i += 1) {
        const free_mask = ~frame_bitmap[i];
        if (free_mask != 0) {
            const bit: u32 = @intCast(@ctz(free_mask));
            return (i * FRAME_BITMAP_WORD_BITS + bit) * PAGE_SIZE;
        }
    }
    return null;
}

fn find_free_frame() ?u32 {
    if (frame_search_word_hint >= BITMAP_SIZE) {
        frame_search_word_hint = 0;
    }
    return find_free_frame_range(frame_search_word_hint, BITMAP_SIZE) orelse
        find_free_frame_range(0, frame_search_word_hint);
}

fn find_contiguous_frames(count: u32) ?u32 {
    if (count == 0) return null;

    var contiguous: u32 = 0;
    var start_frame: u32 = 0;

    var word_index: u32 = 0;
    while (word_index < BITMAP_SIZE) : (word_index += 1) {
        const word = frame_bitmap[word_index];
        if (word == 0) {
            if (contiguous == 0) {
                start_frame = word_index * FRAME_BITMAP_WORD_BITS;
            }
            contiguous += FRAME_BITMAP_WORD_BITS;
            if (contiguous >= count) {
                return start_frame * PAGE_SIZE;
            }
            continue;
        }
        if (word == ~@as(u32, 0)) {
            contiguous = 0;
            continue;
        }
        var bit: u32 = 0;
        while (bit < FRAME_BITMAP_WORD_BITS) : (bit += 1) {
            if ((word >> @truncate(bit)) & 1 == 0) {
                if (contiguous == 0) {
                    start_frame = word_index * FRAME_BITMAP_WORD_BITS + bit;
                }
                contiguous += 1;
                if (contiguous == count) {
                    return start_frame * PAGE_SIZE;
                }
            } else {
                contiguous = 0;
            }
        }
    }
    return null;
}

fn pageDirectoryIndex(virt_addr: u32) u32 {
    return virt_addr >> PAGE_DIRECTORY_SHIFT;
}

fn pageTableIndex(virt_addr: u32) u32 {
    return (virt_addr >> PAGE_SHIFT) & PAGE_TABLE_INDEX_MASK;
}

fn pageOffset(virt_addr: u32) u32 {
    return virt_addr & PAGE_OFFSET_MASK;
}

fn pageAlignedAddress(addr: u32) u32 {
    return addr & ~PAGE_OFFSET_MASK;
}

fn alloc_frame() u32 {
    while (@atomicRmw(bool, &frame_lock, .Xchg, true, .seq_cst)) {
        asm volatile ("pause");
    }
    defer @atomicStore(bool, &frame_lock, false, .seq_cst);

    const frame_addr = find_free_frame() orelse {
        vga.print("Out of memory!\n");
        while (true) {
            asm volatile ("hlt");
        }
    };
    set_frame(frame_addr);
    frame_search_word_hint = (frame_addr / PAGE_SIZE) / FRAME_BITMAP_WORD_BITS;
    return frame_addr;
}

pub fn alloc_frames(count: u32) ?u32 {
    if (count == 0) return null;

    while (@atomicRmw(bool, &frame_lock, .Xchg, true, .seq_cst)) {
        asm volatile ("pause");
    }
    defer @atomicStore(bool, &frame_lock, false, .seq_cst);

    const start_addr = find_contiguous_frames(count);
    if (start_addr) |addr| {
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            set_frame(addr + i * PAGE_SIZE);
        }
        frame_search_word_hint = ((addr / PAGE_SIZE) + (count - 1)) / FRAME_BITMAP_WORD_BITS;
    }
    return start_addr;
}

pub fn mapPage(virt_addr: u32, phys_addr: u32, flags: u32) void {
    const page_dir_index = pageDirectoryIndex(virt_addr);
    const page_table_index = pageTableIndex(virt_addr);

    const page_directory = getCurrentPageDirectory();
    const page_dir_entry = &page_directory[page_dir_index];

    if (!page_dir_entry.present) {
        const table_phys_addr = alloc_frame();
        page_dir_entry.* = PageTableEntry{
            .present = true,
            .writable = true,
            .user = (flags & PAGE_USER) != 0,
            .write_through = (flags & PAGE_WRITE_THROUGH) != 0,
            .cache_disabled = (flags & PAGE_CACHE_DISABLE) != 0,
            .address = @truncate(table_phys_addr >> PAGE_SHIFT),
        };

        const table: *PageTable = @ptrFromInt(table_phys_addr);
        for (table) |*entry| {
            entry.* = PageTableEntry{};
        }
    } else if ((flags & PAGE_USER) != 0 and !page_dir_entry.user) {
        // A directory entry must be at least as permissive as any mapping
        // beneath it: a user PTE under a supervisor-only PDE is unreachable
        // from ring 3. Widening the PDE is safe because the PTE bits still
        // gate access per page.
        page_dir_entry.user = true;
    }

    const table_addr = @as(usize, page_dir_entry.address) << PAGE_SHIFT;
    const table: *PageTable = @ptrFromInt(table_addr);

    table[page_table_index] = PageTableEntry{
        .present = true,
        .writable = (flags & PAGE_WRITABLE) != 0,
        .user = (flags & PAGE_USER) != 0,
        .write_through = (flags & PAGE_WRITE_THROUGH) != 0,
        .cache_disabled = (flags & PAGE_CACHE_DISABLE) != 0,
        .global = (flags & PAGE_GLOBAL) != 0,
        .address = @truncate(phys_addr >> PAGE_SHIFT),
    };
}

/// Clear the writable bit on an existing mapping. Only binding for
/// supervisor-mode writes once CR0.WP is set (see enableWriteProtect).
pub fn setPageReadOnly(virt_addr: u32) void {
    const page_dir_index = pageDirectoryIndex(virt_addr);
    const page_table_index = pageTableIndex(virt_addr);

    const page_directory = getCurrentPageDirectory();
    const page_dir_entry = &page_directory[page_dir_index];
    if (!page_dir_entry.present) return;

    const table_addr = @as(usize, page_dir_entry.address) << PAGE_SHIFT;
    const table: *PageTable = @ptrFromInt(table_addr);

    const page_entry = &table[page_table_index];
    if (!page_entry.present) return;
    page_entry.writable = false;
    invalidate_page(virt_addr);
}

/// Set CR0.WP so read-only pages bind CPL0 writes as well; without it the
/// writable bit only constrains user mode and kernel W^X is theater.
pub fn enableWriteProtect() void {
    asm volatile (
        \\mov %%cr0, %%eax
        \\or $0x10000, %%eax
        \\mov %%eax, %%cr0
        ::: .{ .eax = true });
}

pub fn unmap_page(virt_addr: u32) void {
    const page_dir_index = pageDirectoryIndex(virt_addr);
    const page_table_index = pageTableIndex(virt_addr);

    const page_directory = getCurrentPageDirectory();
    const page_dir_entry = &page_directory[page_dir_index];
    if (!page_dir_entry.present) {
        return;
    }

    const table_addr = @as(usize, page_dir_entry.address) << PAGE_SHIFT;
    const table: *PageTable = @ptrFromInt(table_addr);

    const page_entry = &table[page_table_index];
    if (page_entry.present) {
        page_entry.* = PageTableEntry{};

        invalidate_page(virt_addr);
    }
}

pub fn createUserPageDirectory() !*PageDirectory {
    const pd_phys = alloc_frames(1) orelse return error.OutOfMemory;
    const pd: *PageDirectory = @ptrCast(@alignCast(@as([*]u8, @ptrFromInt(pd_phys))));

    for (pd) |*entry| {
        entry.* = PageTableEntry{};
    }

    for (0..TABLES_PER_DIRECTORY) |i| {
        if (kernel_page_directory[i].present) {
            pd[i] = kernel_page_directory[i];
        }
    }

    return pd;
}

pub fn init() void {
    vga.print("Initializing paging...\n");

    for (&frame_bitmap) |*word| {
        word.* = 0;
    }

    for (&kernel_page_directory) |*entry| {
        entry.* = PageTableEntry{};
    }

    var addr: u32 = 0;
    var table_idx: usize = 0;
    while (table_idx < kernel_page_tables.len) : (table_idx += 1) {
        for (&kernel_page_tables[table_idx]) |*entry| {
            entry.* = PageTableEntry{
                .present = true,
                .writable = true,
                .address = @truncate(addr >> PAGE_SHIFT),
            };
            addr += PAGE_SIZE;
        }

        kernel_page_directory[table_idx] = PageTableEntry{
            .present = true,
            .writable = true,
            .address = @truncate(@intFromPtr(&kernel_page_tables[table_idx]) >> PAGE_SHIFT),
        };
    }

    const kernel_end = memory.getReservedMemoryEnd();
    var i: u32 = 0;
    while (i < kernel_end) : (i += PAGE_SIZE) {
        set_frame(i);
    }
    frame_search_word_hint = (kernel_end / PAGE_SIZE) / FRAME_BITMAP_WORD_BITS;

    enable_paging(@intFromPtr(&kernel_page_directory));
    unmapBootStackGuardPage();
    // The double-fault task switch loads CR3 from its TSS; point it at the
    // kernel page directory now that paging is live.
    @import("../interrupts/gdt.zig").refreshDoubleFaultCr3();
    vga.print("Paging enabled!\n");
    vga.print("Total frames: ");
    numfmt.printDec(total_frames);
    vga.print(" Used frames: ");
    numfmt.printDec(used_frames);
    vga.print("\n");
}

// A boot-stack overflow used to run straight into the device-broker globals
// below stack_bottom and corrupt them silently; Debug builds hit this with
// their larger frames while ReleaseFast masked it. Sacrifice the lowest stack
// page as an unmapped guard so an overflow page-faults at the boundary
// instead. Demand paging only maps heap addresses, so the guard stays
// unmapped for the kernel's lifetime.
fn unmapBootStackGuardPage() void {
    const guard_address: u32 = @intFromPtr(&stack_bottom);
    if (guard_address % PAGE_SIZE != 0) {
        vga.print("Boot stack guard skipped: stack_bottom is not page-aligned\n");
        return;
    }
    unmap_page(guard_address);
}

fn enable_paging(page_dir_addr: u32) void {
    asm volatile (
        \\mov %[addr], %%cr3
        \\mov %%cr0, %%eax
        \\or $0x80000000, %%eax
        \\mov %%eax, %%cr0
        :
        : [addr] "r" (page_dir_addr),
        : .{ .eax = true });
}

pub fn page_fault_handler(regs: *const @import("../interrupts/isr.zig").Registers) void {
    // SAFETY: populated by the subsequent inline assembly reading CR2
    var faulting_address: u32 = undefined;
    asm volatile ("mov %%cr2, %[addr]"
        : [addr] "=r" (faulting_address),
    );

    const present = (regs.err_code & 0x1) == 0;
    const write = (regs.err_code & 0x2) != 0;
    const user = (regs.err_code & 0x4) != 0;
    const reserved = (regs.err_code & 0x8) != 0;
    const instruction_fetch = (regs.err_code & 0x10) != 0;

    if (present) {
        if (handle_demand_paging(faulting_address, write, user)) {
            return;
        }
    }

    const console = @import("../utils/console.zig");
    console.print("\n=== PAGE FAULT ===\n");
    console.print("Address: 0x");
    print_hex_console(faulting_address, console);
    console.print("\n");
    console.print("EIP: 0x");
    print_hex_console(regs.eip, console);
    console.print("\n");

    if (present) console.print("  - Page not present\n");
    if (write) console.print("  - Write violation\n") else console.print("  - Read violation\n");
    if (user) console.print("  - User mode\n") else console.print("  - Kernel mode\n");
    if (reserved) console.print("  - Reserved bit violation\n");
    if (instruction_fetch) console.print("  - Instruction fetch\n");

    // Returning would iret back to the faulting instruction and refault
    // forever; panic instead so the backtrace identifies the culprit and the
    // machine halts for good.
    const panic_utils = @import("../utils/panic.zig");
    panic_utils.panic("unrecoverable page fault at 0x{x:0>8} (eip=0x{x:0>8})", .{ faulting_address, regs.eip });
}

fn print_hex_console(value: u32, console: anytype) void {
    const hex_chars = "0123456789ABCDEF";
    var i: u32 = HEX_HIGH_NIBBLE_SHIFT;
    while (i >= 0) : (i -= HEX_NIBBLE_BITS) {
        const nibble = (value >> @truncate(i)) & HEX_NIBBLE_MASK;
        console.printChar(hex_chars[nibble]);
        if (i == 0) break;
    }
}

// Demand-paged kernel heap range served by handle_demand_paging; the heap
// allocator itself lives in memory.zig.
const HEAP_START: u32 = 0x10000000;
const HEAP_MAX_SIZE: u32 = 16 * 1024 * 1024;

var current_page_directory: *PageDirectory = &kernel_page_directory;

pub fn getCurrentPageDirectory() *PageDirectory {
    return current_page_directory;
}

pub fn switchPageDirectory(pd: *PageDirectory) void {
    current_page_directory = pd;
    // Loading CR3 flushes the non-global TLB entries; no separate flush is
    // needed.
    asm volatile (
        \\mov %[addr], %%cr3
        :
        : [addr] "r" (@intFromPtr(pd)),
    );
}

fn invalidate_page(virt_addr: u32) void {
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt_addr),
    );
}

fn handle_demand_paging(addr: u32, _: bool, user: bool) bool {
    const aligned_addr = pageAlignedAddress(addr);

    if (aligned_addr >= HEAP_START and aligned_addr < HEAP_START + HEAP_MAX_SIZE) {
        const phys = alloc_frame();
        var flags: u32 = PAGE_PRESENT | PAGE_WRITABLE;
        if (user) flags |= PAGE_USER;

        mapPage(aligned_addr, phys, flags);

        const page_ptr: [*]u8 = @ptrFromInt(aligned_addr);
        @memset(page_ptr[0..PAGE_SIZE], 0);

        return true;
    }

    return false;
}

pub fn map_range(virt_start: u32, phys_start: u32, size: u32, flags: u32) void {
    var offset: u32 = 0;
    while (offset < size) : (offset += PAGE_SIZE) {
        mapPage(virt_start + offset, phys_start + offset, flags);
    }
}

fn getPageEntry(page_directory: *PageDirectory, virt_addr: u32) ?*PageTableEntry {
    const page_dir_index = pageDirectoryIndex(virt_addr);
    const page_table_index = pageTableIndex(virt_addr);

    const page_dir_entry = page_directory[page_dir_index];
    if (!page_dir_entry.present) {
        return null;
    }

    const table_addr = @as(usize, page_dir_entry.address) << PAGE_SHIFT;
    const table: *PageTable = @ptrFromInt(table_addr);

    const entry = &table[page_table_index];
    if (!entry.present) {
        return null;
    }
    return entry;
}

fn updatePageEntryFlags(entry: *PageTableEntry, flags: u32) void {
    entry.writable = (flags & PAGE_WRITABLE) != 0;
    entry.user = (flags & PAGE_USER) != 0;
    entry.write_through = (flags & PAGE_WRITE_THROUGH) != 0;
    entry.cache_disabled = (flags & PAGE_CACHE_DISABLE) != 0;
    entry.global = (flags & PAGE_GLOBAL) != 0;
}

pub fn set_current_page_flags(virt_addr: u32, flags: u32) void {
    if (getPageEntry(getCurrentPageDirectory(), virt_addr)) |entry| {
        updatePageEntryFlags(entry, flags);
        invalidate_page(virt_addr);
    }
}
