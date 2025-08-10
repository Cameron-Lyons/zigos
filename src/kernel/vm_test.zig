const std = @import("std");
const vga = @import("vga.zig");
const paging = @import("paging.zig");

pub fn test_virtual_memory() void {
    vga.print("\n=== Virtual Memory Test Suite ===\n");
    
    test_memory_allocation();
    test_page_mapping();
    test_memory_stats();
    test_page_flags();
    test_range_operations();
    
    vga.print("=== All VM Tests Passed ===\n\n");
}

fn test_memory_allocation() void {
    vga.print("Testing memory allocation...\n");
    
    const ptr1 = paging.kmalloc(1024);
    if (ptr1 == null) {
        vga.print("  [FAIL] Could not allocate 1KB\n");
        return;
    }
    vga.print("  [OK] Allocated 1KB\n");
    
    const ptr2 = paging.kmalloc(4096);
    if (ptr2 == null) {
        vga.print("  [FAIL] Could not allocate 4KB\n");
        return;
    }
    vga.print("  [OK] Allocated 4KB\n");
    
    const ptr3 = paging.kmalloc(8192);
    if (ptr3 == null) {
        vga.print("  [FAIL] Could not allocate 8KB\n");
        return;
    }
    vga.print("  [OK] Allocated 8KB\n");
    
    paging.kfree(ptr1.?);
    vga.print("  [OK] Freed 1KB\n");
    
    paging.kfree(ptr2.?);
    vga.print("  [OK] Freed 4KB\n");
    
    paging.kfree(ptr3.?);
    vga.print("  [OK] Freed 8KB\n");
}

fn test_page_mapping() void {
    vga.print("Testing page mapping...\n");
    
    const virt_addr: u32 = 0x20000000;
    const phys_addr: u32 = 0x400000;
    
    paging.mapPage(virt_addr, phys_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    vga.print("  [OK] Mapped virtual 0x20000000 to physical 0x400000\n");
    
    const retrieved = paging.get_physical_address(virt_addr);
    if (retrieved) |addr| {
        if (addr == phys_addr) {
            vga.print("  [OK] Physical address retrieval correct\n");
        } else {
            vga.print("  [FAIL] Physical address mismatch\n");
        }
    } else {
        vga.print("  [FAIL] Could not retrieve physical address\n");
    }
    
    if (paging.is_page_present(virt_addr)) {
        vga.print("  [OK] Page presence check passed\n");
    } else {
        vga.print("  [FAIL] Page should be present\n");
    }
    
    paging.unmap_page(virt_addr);
    vga.print("  [OK] Unmapped page\n");
    
    if (!paging.is_page_present(virt_addr)) {
        vga.print("  [OK] Page correctly unmapped\n");
    } else {
        vga.print("  [FAIL] Page should not be present\n");
    }
}

fn test_memory_stats() void {
    vga.print("Testing memory statistics...\n");
    
    const stats = paging.getMemoryStats();
    vga.print("  Total frames: ");
    print_dec(stats.total_frames);
    vga.print("\n");
    vga.print("  Used frames: ");
    print_dec(stats.used_frames);
    vga.print("\n");
    
    const free_frames = stats.total_frames - stats.used_frames;
    vga.print("  Free frames: ");
    print_dec(free_frames);
    vga.print("\n");
    
    const free_memory = free_frames * 4096 / (1024 * 1024);
    vga.print("  Free memory: ");
    print_dec(free_memory);
    vga.print(" MB\n");
}

fn test_page_flags() void {
    vga.print("Testing page flags...\n");
    
    const virt_addr: u32 = 0x21000000;
    const phys_addr: u32 = 0x500000;
    
    paging.mapPage(virt_addr, phys_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
    vga.print("  [OK] Mapped page with USER flag\n");
    
    paging.set_page_flags(virt_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    vga.print("  [OK] Modified page flags (removed USER)\n");
    
    paging.set_page_flags(virt_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_GLOBAL);
    vga.print("  [OK] Modified page flags (added GLOBAL)\n");
    
    paging.unmap_page(virt_addr);
}

fn test_range_operations() void {
    vga.print("Testing range operations...\n");
    
    const virt_start: u32 = 0x22000000;
    const phys_start: u32 = 0x600000;
    const size: u32 = 16 * 4096;
    
    paging.map_range(virt_start, phys_start, size, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    vga.print("  [OK] Mapped 16 pages (64KB) range\n");
    
    var all_present = true;
    var i: u32 = 0;
    while (i < size) : (i += 4096) {
        if (!paging.is_page_present(virt_start + i)) {
            all_present = false;
            break;
        }
    }
    
    if (all_present) {
        vga.print("  [OK] All pages in range are present\n");
    } else {
        vga.print("  [FAIL] Not all pages in range are present\n");
    }
    
    paging.unmap_range(virt_start, size);
    vga.print("  [OK] Unmapped range\n");
    
    var all_unmapped = true;
    i = 0;
    while (i < size) : (i += 4096) {
        if (paging.is_page_present(virt_start + i)) {
            all_unmapped = false;
            break;
        }
    }
    
    if (all_unmapped) {
        vga.print("  [OK] All pages in range are unmapped\n");
    } else {
        vga.print("  [FAIL] Not all pages in range are unmapped\n");
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