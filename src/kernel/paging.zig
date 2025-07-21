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

const MEMORY_SIZE = 128 * 1024 * 1024;
const FRAME_COUNT = MEMORY_SIZE / PAGE_SIZE;
const BITMAP_SIZE = FRAME_COUNT / 32;

var frame_bitmap: [BITMAP_SIZE]u32 = undefined;
var total_frames: u32 = FRAME_COUNT;
var used_frames: u32 = 0;

fn set_frame(frame_addr: u32) void {
    const frame = frame_addr / PAGE_SIZE;
    const idx = frame / 32;
    const offset = frame % 32;
    frame_bitmap[idx] |= (@as(u32, 1) << @truncate(offset));
    used_frames += 1;
}

fn clear_frame(frame_addr: u32) void {
    const frame = frame_addr / PAGE_SIZE;
    const idx = frame / 32;
    const offset = frame % 32;
    frame_bitmap[idx] &= ~(@as(u32, 1) << @truncate(offset));
    used_frames -= 1;
}

fn test_frame(frame_addr: u32) bool {
    const frame = frame_addr / PAGE_SIZE;
    const idx = frame / 32;
    const offset = frame % 32;
    return (frame_bitmap[idx] & (@as(u32, 1) << @truncate(offset))) != 0;
}

fn find_free_frame() ?u32 {
    var i: u32 = 0;
    while (i < BITMAP_SIZE) : (i += 1) {
        if (frame_bitmap[i] != 0xFFFFFFFF) {
            var j: u32 = 0;
            while (j < 32) : (j += 1) {
                const mask = @as(u32, 1) << @truncate(j);
                if ((frame_bitmap[i] & mask) == 0) {
                    return (i * 32 + j) * PAGE_SIZE;
                }
            }
        }
    }
    return null;
}

fn alloc_frame() u32 {
    const frame_addr = find_free_frame() orelse {
        vga.print("Out of memory!\n");
        asm volatile ("hlt");
    };
    set_frame(frame_addr);
    return frame_addr;
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

pub fn unmap_page(virt_addr: u32) void {
    const page_dir_index = virt_addr >> 22;
    const page_table_index = (virt_addr >> 12) & 0x3FF;
    
    const page_dir_entry = &kernel_page_directory[page_dir_index];
    if (!page_dir_entry.present) {
        return;
    }
    
    const table_addr = @as(usize, page_dir_entry.address) << 12;
    const table = @as(*PageTable, @ptrFromInt(table_addr));
    
    const page_entry = &table[page_table_index];
    if (page_entry.present) {
        const phys_addr = @as(u32, page_entry.address) << 12;
        clear_frame(phys_addr);
        page_entry.* = PageTableEntry{};
        
        asm volatile ("invlpg (%[addr])"
            :
            : [addr] "r" (virt_addr),
        );
    }
}

pub fn remap_page(virt_addr: u32, new_phys_addr: u32, flags: u32) void {
    unmap_page(virt_addr);
    map_page(virt_addr, new_phys_addr, flags);
}

pub fn get_physical_address(virt_addr: u32) ?u32 {
    const page_dir_index = virt_addr >> 22;
    const page_table_index = (virt_addr >> 12) & 0x3FF;
    const offset = virt_addr & 0xFFF;
    
    const page_dir_entry = kernel_page_directory[page_dir_index];
    if (!page_dir_entry.present) {
        return null;
    }
    
    const table_addr = @as(usize, page_dir_entry.address) << 12;
    const table = @as(*const PageTable, @ptrFromInt(table_addr));
    
    const page_entry = table[page_table_index];
    if (!page_entry.present) {
        return null;
    }
    
    return (@as(u32, page_entry.address) << 12) | offset;
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
    while (table_idx < 4) : (table_idx += 1) {
        for (&kernel_page_tables[table_idx]) |*entry| {
            entry.* = PageTableEntry{
                .present = true,
                .writable = true,
                .address = @truncate(addr >> 12),
            };
            set_frame(addr);
            addr += PAGE_SIZE;
        }

        kernel_page_directory[table_idx] = PageTableEntry{
            .present = true,
            .writable = true,
            .address = @truncate(@intFromPtr(&kernel_page_tables[table_idx]) >> 12),
        };
    }

    const kernel_end = 16 * 1024 * 1024;
    var i: u32 = 0;
    while (i < kernel_end) : (i += PAGE_SIZE) {
        set_frame(i);
    }

    enable_paging(@intFromPtr(&kernel_page_directory));
    vga.print("Paging enabled!\n");
    vga.print("Total frames: ");
    print_dec(total_frames);
    vga.print(" Used frames: ");
    print_dec(used_frames);
    vga.print("\n");
    
    init_heap();
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
        : [addr] "=r" (faulting_address),
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

fn print_dec(value: u32) void {
    if (value == 0) {
        vga.put_char('0');
        return;
    }
    
    var buffer: [10]u8 = undefined;
    var i: usize = 0;
    var n = value;
    
    while (n > 0) : (i += 1) {
        buffer[i] = @truncate((n % 10) + '0');
        n /= 10;
    }
    
    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}

const HEAP_START: u32 = 0x10000000;
const HEAP_INITIAL_SIZE: u32 = 1024 * 1024;
const HEAP_MAX_SIZE: u32 = 16 * 1024 * 1024;

const BlockHeader = packed struct {
    size: u32,
    is_free: bool,
    magic: u31 = 0x1234567,
};

var heap_start: u32 = HEAP_START;
var heap_end: u32 = HEAP_START;
var heap_max: u32 = HEAP_START + HEAP_MAX_SIZE;

pub fn init_heap() void {
    heap_end = heap_start + HEAP_INITIAL_SIZE;
    
    var current_addr = heap_start;
    while (current_addr < heap_end) : (current_addr += PAGE_SIZE) {
        const frame = alloc_frame();
        map_page(current_addr, frame, PAGE_PRESENT | PAGE_WRITABLE);
    }
    
    const initial_block = @as(*BlockHeader, @ptrFromInt(heap_start));
    initial_block.* = BlockHeader{
        .size = HEAP_INITIAL_SIZE - @sizeOf(BlockHeader),
        .is_free = true,
    };
    
    vga.print("Heap initialized at 0x");
    print_hex(heap_start);
    vga.print(" size: ");
    print_dec(HEAP_INITIAL_SIZE);
    vga.print("\n");
}

fn find_best_fit(size: u32) ?*BlockHeader {
    var current = @as(*BlockHeader, @ptrFromInt(heap_start));
    var best_fit: ?*BlockHeader = null;
    var best_size: u32 = 0xFFFFFFFF;
    
    while (@intFromPtr(current) < heap_end) {
        if (current.is_free and current.size >= size and current.size < best_size) {
            best_fit = current;
            best_size = current.size;
        }
        
        const next_addr = @intFromPtr(current) + @sizeOf(BlockHeader) + current.size;
        if (next_addr >= heap_end) break;
        current = @as(*BlockHeader, @ptrFromInt(next_addr));
    }
    
    return best_fit;
}

fn expand_heap(size: u32) bool {
    const required_size = size + @sizeOf(BlockHeader);
    const new_pages = (required_size + PAGE_SIZE - 1) / PAGE_SIZE;
    const new_size = new_pages * PAGE_SIZE;
    
    if (heap_end + new_size > heap_max) {
        return false;
    }
    
    var current_addr = heap_end;
    const new_end = heap_end + new_size;
    while (current_addr < new_end) : (current_addr += PAGE_SIZE) {
        const frame = alloc_frame();
        map_page(current_addr, frame, PAGE_PRESENT | PAGE_WRITABLE);
    }
    
    const new_block = @as(*BlockHeader, @ptrFromInt(heap_end));
    new_block.* = BlockHeader{
        .size = new_size - @sizeOf(BlockHeader),
        .is_free = true,
    };
    
    heap_end = new_end;
    return true;
}

pub fn kmalloc(size: u32) ?*anyopaque {
    const aligned_size = (size + 7) & ~@as(u32, 7);
    
    var block = find_best_fit(aligned_size);
    if (block == null) {
        if (!expand_heap(aligned_size)) {
            vga.print("kmalloc: out of memory!\n");
            return null;
        }
        block = find_best_fit(aligned_size);
    }
    
    const header = block.?;
    
    if (header.size > aligned_size + @sizeOf(BlockHeader) + 16) {
        const remaining_size = header.size - aligned_size - @sizeOf(BlockHeader);
        const new_block_addr = @intFromPtr(header) + @sizeOf(BlockHeader) + aligned_size;
        const new_block = @as(*BlockHeader, @ptrFromInt(new_block_addr));
        new_block.* = BlockHeader{
            .size = remaining_size,
            .is_free = true,
        };
        header.size = aligned_size;
    }
    
    header.is_free = false;
    return @as(*anyopaque, @ptrFromInt(@intFromPtr(header) + @sizeOf(BlockHeader)));
}

pub fn kfree(ptr: *anyopaque) void {
    const header_addr = @intFromPtr(ptr) - @sizeOf(BlockHeader);
    const header = @as(*BlockHeader, @ptrFromInt(header_addr));
    
    if (header.magic != 0x1234567) {
        vga.print("kfree: invalid magic number!\n");
        return;
    }
    
    header.is_free = true;
    
    coalesce_free_blocks();
}

fn coalesce_free_blocks() void {
    var current = @as(*BlockHeader, @ptrFromInt(heap_start));
    
    while (@intFromPtr(current) < heap_end) {
        if (current.is_free) {
            const next_addr = @intFromPtr(current) + @sizeOf(BlockHeader) + current.size;
            if (next_addr < heap_end) {
                const next = @as(*BlockHeader, @ptrFromInt(next_addr));
                if (next.is_free) {
                    current.size += @sizeOf(BlockHeader) + next.size;
                    continue;
                }
            }
        }
        
        const next_addr = @intFromPtr(current) + @sizeOf(BlockHeader) + current.size;
        if (next_addr >= heap_end) break;
        current = @as(*BlockHeader, @ptrFromInt(next_addr));
    }
}

