const vga = @import("vga.zig");

const PAGE_SIZE = 4096;
const PAGES_PER_TABLE = 1024;
const TABLES_PER_DIRECTORY = 1024;

const PAGE_PRESENT: u32 = 0x1;
const PAGE_WRITABLE: u32 = 0x2;
const PAGE_USER: u32 = 0x4;
const PAGE_SIZE_4MB: u32 = 0x80;

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

var kernel_page_directory: PageDirectory align(PAGE_SIZE) = undefined;
var kernel_page_tables: [4]PageTable align(PAGE_SIZE) = undefined;

var next_free_frame: u32 = 0x100000;

fn alloc_frame() u32 {
    const frame = next_free_frame;
    next_free_frame += PAGE_SIZE;
    return frame;
}

fn map_page(virt_addr: u32, phys_addr: u32, flags: u32) void {
    const page_dir_index = virt_addr >> 22;
    const page_table_index = (virt_addr >> 12) & 0x3FF;
    
    const page_dir_entry = &kernel_page_directory[page_dir_index];
    
    if (!page_dir_entry.present) {
        const table_phys_addr = alloc_frame();
        page_dir_entry.* = PageTableEntry{
            .present = true,
            .writable = true,
            .user = (flags & PAGE_USER) != 0,
            .address = @truncate(table_phys_addr >> 12),
        };
        
        const table = @as(*PageTable, @ptrFromInt(table_phys_addr));
        for (table) |*entry| {
            entry.* = PageTableEntry{};
        }
    }
    
    const table_addr = @as(usize, page_dir_entry.address) << 12;
    const table = @as(*PageTable, @ptrFromInt(table_addr));
    
    table[page_table_index] = PageTableEntry{
        .present = true,
        .writable = (flags & PAGE_WRITABLE) != 0,
        .user = (flags & PAGE_USER) != 0,
        .address = @truncate(phys_addr >> 12),
    };
}

pub fn init() void {
    vga.print("Initializing paging...\n");
    
    for (&kernel_page_directory) |*entry| {
        entry.* = PageTableEntry{};
    }
    
    var addr: u32 = 0;
    var table_idx: usize = 0;
    while (table_idx < 4) : (table_idx += 1) {
        for (&kernel_page_tables[table_idx]) |*entry| {
            entry.* = PageTableEntry{
                .present = true,
                .writable = true,
                .address = @truncate(addr >> 12),
            };
            addr += PAGE_SIZE;
        }
        
        kernel_page_directory[table_idx] = PageTableEntry{
            .present = true,
            .writable = true,
            .address = @truncate(@intFromPtr(&kernel_page_tables[table_idx]) >> 12),
        };
    }
    
    enable_paging(@intFromPtr(&kernel_page_directory));
    vga.print("Paging enabled!\n");
}

fn enable_paging(page_dir_addr: u32) void {
    asm volatile (
        \\mov %[addr], %%cr3
        \\mov %%cr0, %%eax
        \\or $0x80000000, %%eax
        \\mov %%eax, %%cr0
        :
        : [addr] "r" (page_dir_addr),
        : "eax"
    );
}

pub fn page_fault_handler(regs: *const @import("isr.zig").Registers) void {
    var faulting_address: u32 = undefined;
    asm volatile ("mov %%cr2, %[addr]"
        : [addr] "=r" (faulting_address)
    );
    
    vga.print("Page fault at address: 0x");
    print_hex(faulting_address);
    vga.print("\n");
    
    const present = (regs.err_code & 0x1) == 0;
    const write = (regs.err_code & 0x2) != 0;
    const user = (regs.err_code & 0x4) != 0;
    
    if (present) vga.print("Page not present\n");
    if (write) vga.print("Write violation\n");
    if (user) vga.print("User mode violation\n");
    
    asm volatile ("hlt");
}

fn print_hex(value: u32) void {
    const hex_chars = "0123456789ABCDEF";
    var i: u32 = 28;
    while (i >= 0) : (i -= 4) {
        const nibble = (value >> @truncate(i)) & 0xF;
        vga.put_char(hex_chars[nibble]);
        if (i == 0) break;
    }
}