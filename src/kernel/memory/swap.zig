const paging = @import("paging.zig");
const memory = @import("memory.zig");
const ata = @import("../drivers/ata.zig");
const vga = @import("../drivers/vga.zig");

const PAGE_SIZE = 4096;
const SWAP_SLOT_COUNT = 8192;
const SWAP_START_LBA: u64 = 2048;
const SECTORS_PER_PAGE = PAGE_SIZE / 512;

const SwapFlags = struct {
    const PRESENT: u8 = 1 << 0;
    const DIRTY: u8 = 1 << 1;
    const SWAPPED: u8 = 1 << 2;
};

pub const SwapEntry = struct {
    slot: u32,
    flags: u8,
};

pub const SwapStats = struct {
    free_slots: u32,
    used_slots: u32,
    total_slots: u32,
};

var swap_table: [SWAP_SLOT_COUNT]SwapEntry = [_]SwapEntry{SwapEntry{ .slot = 0, .flags = 0 }} ** SWAP_SLOT_COUNT;
var swap_bitmap: [SWAP_SLOT_COUNT / 32]u32 = [_]u32{0} ** (SWAP_SLOT_COUNT / 32);
var used_swap_slots: u32 = 0;
var clock_hand: u32 = 0;
var initialized: bool = false;
var swap_search_word_hint: u32 = 0;

pub fn init() void {
    for (&swap_table) |*entry| {
        entry.slot = 0;
        entry.flags = 0;
    }

    for (&swap_bitmap) |*word| {
        word.* = 0;
    }

    used_swap_slots = 0;
    clock_hand = 0;
    swap_search_word_hint = 0;
    initialized = true;

    vga.print("Swap initialized: ");
    printDec(SWAP_SLOT_COUNT);
    vga.print(" slots (");
    printDec(SWAP_SLOT_COUNT * PAGE_SIZE / 1024 / 1024);
    vga.print(" MB)\n");
}

fn allocSwapSlotRange(start_word: u32, end_word: u32) ?u32 {
    var i = start_word;
    while (i < end_word) : (i += 1) {
        const free_mask = ~swap_bitmap[i];
        if (free_mask != 0) {
            const bit: u32 = @intCast(@ctz(free_mask));
            const mask = @as(u32, 1) << @truncate(bit);
            swap_bitmap[i] |= mask;
            used_swap_slots += 1;
            swap_search_word_hint = i;
            return i * 32 + bit;
        }
    }
    return null;
}

fn allocSwapSlot() ?u32 {
    const bitmap_words = SWAP_SLOT_COUNT / 32;
    if (swap_search_word_hint >= bitmap_words) {
        swap_search_word_hint = 0;
    }
    return allocSwapSlotRange(swap_search_word_hint, bitmap_words) orelse
        allocSwapSlotRange(0, swap_search_word_hint);
}

fn freeSwapSlot(slot: u32) void {
    const idx = slot / 32;
    const offset: u5 = @truncate(slot % 32);
    const mask = @as(u32, 1) << offset;
    if ((swap_bitmap[idx] & mask) != 0) {
        swap_bitmap[idx] &= ~mask;
        used_swap_slots -= 1;
        if (idx < swap_search_word_hint) {
            swap_search_word_hint = idx;
        }
    }
}

fn writePageToDisk(slot: u32, page_data: [*]const u8) bool {
    const device = ata.getPrimaryMaster() orelse return false;
    const lba = SWAP_START_LBA + @as(u64, slot) * SECTORS_PER_PAGE;

    ata.writeSectors(device, lba, SECTORS_PER_PAGE, page_data[0..PAGE_SIZE]) catch {
        return false;
    };
    return true;
}

fn readPageFromDisk(slot: u32, page_data: [*]u8) bool {
    const device = ata.getPrimaryMaster() orelse return false;
    const lba = SWAP_START_LBA + @as(u64, slot) * SECTORS_PER_PAGE;

    ata.readSectors(device, lba, SECTORS_PER_PAGE, page_data[0..PAGE_SIZE]) catch {
        return false;
    };
    return true;
}

fn heapTableIndex(aligned_addr: u32) u32 {
    return (aligned_addr - paging.KERNEL_HEAP_START) / PAGE_SIZE;
}

pub fn clockAlgorithm() ?u32 {
    const heap_start = paging.KERNEL_HEAP_START;
    const heap_max = paging.KERNEL_HEAP_START + paging.KERNEL_HEAP_MAX_SIZE;
    const total_pages = (heap_max - heap_start) / PAGE_SIZE;

    var scanned: u32 = 0;
    while (scanned < total_pages * 2) : (scanned += 1) {
        const vaddr = heap_start + clock_hand * PAGE_SIZE;
        clock_hand = (clock_hand + 1) % total_pages;

        if (!paging.is_page_present(vaddr)) continue;

        const page_dir_index = vaddr >> 22;
        const page_table_index = (vaddr >> 12) & 0x3FF;

        const pd = paging.getCurrentPageDirectory();
        if (!pd[page_dir_index].present) continue;

        const table_addr = @as(usize, pd[page_dir_index].address) << 12;
        const table: *paging.PageTable = @ptrFromInt(table_addr);
        const entry = &table[page_table_index];

        if (entry.accessed) {
            entry.accessed = false;
            paging.invalidate_page(vaddr);
            continue;
        }

        return vaddr;
    }
    return null;
}

pub fn swapOut(vaddr: u32) !void {
    if (!initialized) return error.NotInitialized;

    const aligned_addr = vaddr & ~@as(u32, PAGE_SIZE - 1);

    if (!paging.is_page_present(aligned_addr)) return error.PageNotPresent;

    const slot = allocSwapSlot() orelse return error.SwapFull;

    const page_data: [*]const u8 = @ptrFromInt(aligned_addr);
    if (!writePageToDisk(slot, page_data)) {
        freeSwapSlot(slot);
        return error.DiskWriteError;
    }

    const table_index = heapTableIndex(aligned_addr);
    if (table_index < SWAP_SLOT_COUNT) {
        swap_table[table_index] = SwapEntry{
            .slot = slot,
            .flags = SwapFlags.SWAPPED,
        };
    }

    paging.unmap_page(aligned_addr);
}

pub fn swapIn(vaddr: u32) !void {
    if (!initialized) return error.NotInitialized;

    const aligned_addr = vaddr & ~@as(u32, PAGE_SIZE - 1);
    const table_index = heapTableIndex(aligned_addr);

    if (table_index >= SWAP_SLOT_COUNT) return error.InvalidAddress;

    const entry = &swap_table[table_index];
    if (entry.flags & SwapFlags.SWAPPED == 0) return error.NotSwapped;

    const frame = paging.alloc_frames(1) orelse {
        return error.OutOfMemory;
    };

    paging.mapPage(aligned_addr, frame, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);

    const page_data: [*]u8 = @ptrFromInt(aligned_addr);
    if (!readPageFromDisk(entry.slot, page_data)) {
        paging.unmap_page(aligned_addr);
        return error.DiskReadError;
    }

    freeSwapSlot(entry.slot);
    entry.flags = SwapFlags.PRESENT;
    entry.slot = 0;
}

pub fn isSwapped(vaddr: u32) bool {
    const aligned_addr = vaddr & ~@as(u32, PAGE_SIZE - 1);
    if (aligned_addr < paging.KERNEL_HEAP_START) return false;

    const table_index = heapTableIndex(aligned_addr);
    if (table_index >= SWAP_SLOT_COUNT) return false;

    return swap_table[table_index].flags & SwapFlags.SWAPPED != 0;
}

pub fn tryFreeFrame() bool {
    if (!initialized) return false;

    const victim = clockAlgorithm() orelse return false;

    swapOut(victim) catch return false;
    return true;
}

pub fn getSwapStats() SwapStats {
    return SwapStats{
        .free_slots = SWAP_SLOT_COUNT - used_swap_slots,
        .used_slots = used_swap_slots,
        .total_slots = SWAP_SLOT_COUNT,
    };
}

fn printDec(value: u32) void {
    if (value == 0) {
        vga.put_char('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
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
