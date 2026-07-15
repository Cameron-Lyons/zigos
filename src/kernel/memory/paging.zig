const std = @import("std");
const handoff = @import("../boot/handoff.zig");
const vga = @import("../drivers/vga.zig");
const memory = @import("memory.zig");
const numfmt = @import("../utils/numfmt.zig");
const frame_allocator = @import("frame_allocator.zig");
const firmware_memory_map = @import("firmware_memory_map.zig");

const PAGE_SIZE = 4096;
const PAGE_SHIFT = 12;
const PAGES_PER_TABLE = 1024;
const TABLES_PER_DIRECTORY = 1024;
const PAGE_DIRECTORY_SHIFT = 22;
const PAGE_TABLE_INDEX_MASK: u32 = PAGES_PER_TABLE - 1;
const PAGE_OFFSET_MASK: u32 = PAGE_SIZE - 1;
const HEX_NIBBLE_BITS = 4;
const HEX_HIGH_NIBBLE_SHIFT: u32 = 28;
const HEX_NIBBLE_MASK: u32 = 0xF;
const MAX_U32: u32 = ~@as(u32, 0);

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

pub const FrameRun = frame_allocator.FrameRun;
pub const FrameStats = frame_allocator.Stats;
pub const FrameReleaseError = frame_allocator.Error;

pub const UserAddressSpace = struct {
    directory: *PageDirectory,
};

pub const UserPermissions = struct {
    writable: bool,
    write_through: bool = false,
    cache_disabled: bool = false,
};

pub const UserMapError = error{
    OutOfMemory,
    InvalidRange,
    AddressOverflow,
    KernelMappingCollision,
    AlreadyMapped,
};

pub const UserWriteError = error{
    InvalidRange,
    AddressOverflow,
    PageNotOwned,
};

pub const UserAddressSpaceDestroyError = error{
    AddressSpaceActive,
};

const MEMORY_SIZE: u32 = 128 * 1024 * 1024;
const IDENTITY_MAPPED_TABLES = MEMORY_SIZE / (PAGE_SIZE * PAGES_PER_TABLE);

// x86 leaves three software-defined bits in every 32-bit paging entry. PDE
// tags describe who owns the page-table frame; PTE tags describe who owns the
// mapped leaf frame. Zero intentionally means borrowed/inherited so the
// statically built identity map remains non-reclaimable.
const TABLE_OWNER_INHERITED: u3 = 0;
const TABLE_OWNER_KERNEL_DYNAMIC: u3 = 1;
const TABLE_OWNER_USER_PRIVATE: u3 = 2;
const PAGE_OWNER_BORROWED: u3 = 0;
const PAGE_OWNER_USER_PRIVATE: u3 = 1;

// Lowest address of the BSP boot stack, page-aligned in boot64.S. The stack
// grows down toward the kernel globals placed just below it in .bss.
extern var stack_bottom: u8;

// SAFETY: fully initialized in init() which identity-maps the first 128MB
var kernel_page_directory: PageDirectory align(PAGE_SIZE) = undefined;
// SAFETY: fully initialized in init() which identity-maps the first 128MB
var kernel_page_tables: [IDENTITY_MAPPED_TABLES]PageTable align(PAGE_SIZE) = undefined;

const PhysicalFrameAllocator = frame_allocator.Fixed(MEMORY_SIZE, PAGE_SIZE);

// SAFETY: reset and populated in init() before any frame allocation.
var physical_frames = PhysicalFrameAllocator.init();
var frame_lock: bool = false;

fn pageDirectoryIndex(virt_addr: u32) u32 {
    return virt_addr >> PAGE_DIRECTORY_SHIFT;
}

fn pageTableIndex(virt_addr: u32) u32 {
    return (virt_addr >> PAGE_SHIFT) & PAGE_TABLE_INDEX_MASK;
}

fn pageOffset(virt_addr: u32) u32 {
    return virt_addr & PAGE_OFFSET_MASK;
}

fn acquireFrameLock() void {
    while (@atomicRmw(bool, &frame_lock, .Xchg, true, .seq_cst)) {
        asm volatile ("pause");
    }
}

fn releaseFrameLock() void {
    @atomicStore(bool, &frame_lock, false, .seq_cst);
}

fn haltWithMessage(message: []const u8) noreturn {
    vga.print(message);
    while (true) {
        asm volatile ("hlt");
    }
}

fn tryAllocFrame() ?u32 {
    acquireFrameLock();
    defer releaseFrameLock();

    const run = physical_frames.allocate(1) orelse return null;
    return run.base;
}

pub fn alloc_frames(count: u32) ?u32 {
    acquireFrameLock();
    defer releaseFrameLock();

    const run = physical_frames.allocate(count) orelse return null;
    return run.base;
}

pub fn release_frames(base: u32, count: u32) FrameReleaseError!void {
    acquireFrameLock();
    defer releaseFrameLock();

    try physical_frames.release(.{ .base = base, .count = count });
}

pub fn frameStats() FrameStats {
    acquireFrameLock();
    defer releaseFrameLock();

    return physical_frames.stats();
}

fn pageTableFromEntry(entry: PageTableEntry) *PageTable {
    const table_addr = @as(usize, entry.address) << PAGE_SHIFT;
    return @ptrFromInt(table_addr);
}

fn mapBorrowedPageIn(
    page_directory: *PageDirectory,
    virt_addr: u32,
    phys_addr: u32,
    flags: u32,
    table_owner: u3,
) UserMapError!void {
    if (pageOffset(virt_addr) != 0 or pageOffset(phys_addr) != 0) {
        return error.InvalidRange;
    }

    const page_dir_index = pageDirectoryIndex(virt_addr);
    const page_table_index = pageTableIndex(virt_addr);
    const page_dir_entry = &page_directory[page_dir_index];

    if (!page_dir_entry.present) {
        const table_phys_addr = tryAllocFrame() orelse return error.OutOfMemory;
        page_dir_entry.* = PageTableEntry{
            .present = true,
            .writable = true,
            .user = (flags & PAGE_USER) != 0,
            .write_through = (flags & PAGE_WRITE_THROUGH) != 0,
            .cache_disabled = (flags & PAGE_CACHE_DISABLE) != 0,
            .available = table_owner,
            .address = @truncate(table_phys_addr >> PAGE_SHIFT),
        };

        const table: *PageTable = pageTableFromEntry(page_dir_entry.*);
        for (table) |*entry| {
            entry.* = PageTableEntry{};
        }
    } else {
        if (table_owner == TABLE_OWNER_USER_PRIVATE and page_dir_entry.available != TABLE_OWNER_USER_PRIVATE) {
            return error.KernelMappingCollision;
        }
        if ((flags & PAGE_USER) != 0 and !page_dir_entry.user) {
            if (page_dir_entry.available != TABLE_OWNER_USER_PRIVATE) {
                return error.KernelMappingCollision;
            }
            // Only a private directory entry may be widened for a user PTE.
            // Inherited kernel tables are never mutated through a user space.
            page_dir_entry.user = true;
        }
    }

    const table = pageTableFromEntry(page_dir_entry.*);
    const page_entry = &table[page_table_index];
    if (page_entry.present and page_entry.available == PAGE_OWNER_USER_PRIVATE) {
        return error.AlreadyMapped;
    }

    page_entry.* = PageTableEntry{
        .present = true,
        .writable = (flags & PAGE_WRITABLE) != 0,
        .user = (flags & PAGE_USER) != 0,
        .write_through = (flags & PAGE_WRITE_THROUGH) != 0,
        .cache_disabled = (flags & PAGE_CACHE_DISABLE) != 0,
        .global = (flags & PAGE_GLOBAL) != 0,
        .available = PAGE_OWNER_BORROWED,
        .address = @truncate(phys_addr >> PAGE_SHIFT),
    };

    if (page_directory == getCurrentPageDirectory()) {
        invalidate_page(virt_addr);
    }
}

fn mapFailure(error_value: UserMapError) noreturn {
    switch (error_value) {
        error.OutOfMemory => haltWithMessage("Out of physical memory while mapping page!\n"),
        error.InvalidRange => haltWithMessage("Attempted to map an unaligned page!\n"),
        error.KernelMappingCollision => haltWithMessage("User mapping collided with inherited kernel memory!\n"),
        error.AlreadyMapped => haltWithMessage("Attempted to replace an owned user page!\n"),
        error.AddressOverflow => haltWithMessage("Page mapping address overflow!\n"),
    }
}

/// Maps device or firmware memory into the kernel without transferring frame
/// ownership to paging. Dynamic page-table frames remain kernel-owned.
pub fn mapKernelBorrowedPage(virt_addr: u32, phys_addr: u32, flags: u32) void {
    mapBorrowedPageIn(
        &kernel_page_directory,
        virt_addr,
        phys_addr,
        flags & ~PAGE_USER,
        TABLE_OWNER_KERNEL_DYNAMIC,
    ) catch |err| mapFailure(err);
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

/// Removes a borrowed current-space PTE without releasing its physical frame.
/// Owned user mappings must be reclaimed by destroyUserAddressSpace.
pub fn unmapBorrowedCurrentPage(virt_addr: u32) bool {
    const page_dir_index = pageDirectoryIndex(virt_addr);
    const page_table_index = pageTableIndex(virt_addr);

    const page_directory = getCurrentPageDirectory();
    const page_dir_entry = &page_directory[page_dir_index];
    if (!page_dir_entry.present) {
        return false;
    }

    const table = pageTableFromEntry(page_dir_entry.*);

    const page_entry = &table[page_table_index];
    if (!page_entry.present or page_entry.available != PAGE_OWNER_BORROWED) {
        return false;
    }

    page_entry.* = PageTableEntry{};
    invalidate_page(virt_addr);
    return true;
}

pub fn createUserAddressSpace() error{OutOfMemory}!UserAddressSpace {
    const pd_phys = tryAllocFrame() orelse return error.OutOfMemory;
    const pd: *PageDirectory = @ptrCast(@alignCast(@as([*]u8, @ptrFromInt(pd_phys))));

    for (pd) |*entry| {
        entry.* = PageTableEntry{};
    }

    for (0..TABLES_PER_DIRECTORY) |i| {
        if (kernel_page_directory[i].present) {
            pd[i] = kernel_page_directory[i];
        }
    }

    return .{ .directory = pd };
}

/// Allocates zeroed backing one frame at a time and maps it only into the
/// supplied user address space. Page-granular allocation avoids false OOM
/// when physical memory is fragmented. On failure, the caller must destroy
/// the address space; any pages installed before the failure remain owned by
/// it and are reclaimed by the destructor.
pub fn mapOwnedUserRange(
    space: *UserAddressSpace,
    virtual_start: u32,
    size_bytes: u32,
    permissions: UserPermissions,
) UserMapError!void {
    if (pageOffset(virtual_start) != 0 or size_bytes == 0) {
        return error.InvalidRange;
    }
    if (size_bytes > MAX_U32 - (PAGE_SIZE - 1)) {
        return error.AddressOverflow;
    }

    const mapped_size = (size_bytes + PAGE_SIZE - 1) & ~PAGE_OFFSET_MASK;
    if (virtual_start > MAX_U32 - mapped_size) {
        return error.AddressOverflow;
    }

    // Reject the complete range before allocating anything. In particular,
    // user mappings may not widen or write through a copied kernel PDE.
    var offset: u32 = 0;
    while (offset < mapped_size) : (offset += PAGE_SIZE) {
        const virtual_address = virtual_start + offset;
        const page_dir_entry = space.directory[pageDirectoryIndex(virtual_address)];
        if (!page_dir_entry.present) continue;
        if (page_dir_entry.available != TABLE_OWNER_USER_PRIVATE) {
            return error.KernelMappingCollision;
        }

        const table = pageTableFromEntry(page_dir_entry);
        if (table[pageTableIndex(virtual_address)].present) {
            return error.AlreadyMapped;
        }
    }

    // Page tables are tagged as soon as they are installed. If this operation
    // later runs out of frames, they remain owned by `space` and are reclaimed
    // by its destructor (or reused by a retry).
    offset = 0;
    while (offset < mapped_size) : (offset += PAGE_SIZE) {
        const virtual_address = virtual_start + offset;
        const page_dir_entry = &space.directory[pageDirectoryIndex(virtual_address)];
        if (!page_dir_entry.present) {
            const table_phys = tryAllocFrame() orelse return error.OutOfMemory;
            page_dir_entry.* = PageTableEntry{
                .present = true,
                .writable = true,
                .user = true,
                .available = TABLE_OWNER_USER_PRIVATE,
                .address = @truncate(table_phys >> PAGE_SHIFT),
            };

            const table = pageTableFromEntry(page_dir_entry.*);
            for (table) |*entry| {
                entry.* = PageTableEntry{};
            }
        } else {
            page_dir_entry.writable = true;
            page_dir_entry.user = true;
        }
    }

    offset = 0;
    while (offset < mapped_size) : (offset += PAGE_SIZE) {
        const virtual_address = virtual_start + offset;
        const page_phys = tryAllocFrame() orelse return error.OutOfMemory;
        const kernel_alias: [*]u8 = @ptrFromInt(page_phys);
        @memset(kernel_alias[0..PAGE_SIZE], 0);
        const page_dir_entry = space.directory[pageDirectoryIndex(virtual_address)];
        const table = pageTableFromEntry(page_dir_entry);
        table[pageTableIndex(virtual_address)] = PageTableEntry{
            .present = true,
            .writable = permissions.writable,
            .user = true,
            .write_through = permissions.write_through,
            .cache_disabled = permissions.cache_disabled,
            .available = PAGE_OWNER_USER_PRIVATE,
            .address = @truncate(page_phys >> PAGE_SHIFT),
        };
    }
}

/// Copies bytes through the kernel identity alias into pages owned by the
/// supplied user address space. This does not require activating its CR3 and
/// therefore never opens a writable user mapping just to populate code.
pub fn writeOwnedUserRange(
    space: *const UserAddressSpace,
    virtual_start: u32,
    source: []const u8,
) UserWriteError!void {
    if (source.len == 0) return;
    const byte_count = std.math.cast(u32, source.len) orelse return error.AddressOverflow;
    if (virtual_start > MAX_U32 - byte_count) return error.AddressOverflow;

    var copied: usize = 0;
    while (copied < source.len) {
        const virtual_address = virtual_start + @as(u32, @intCast(copied));
        const page_dir_entry = space.directory[pageDirectoryIndex(virtual_address)];
        if (!page_dir_entry.present or page_dir_entry.available != TABLE_OWNER_USER_PRIVATE) {
            return error.PageNotOwned;
        }
        const table = pageTableFromEntry(page_dir_entry);
        const page_entry = table[pageTableIndex(virtual_address)];
        if (!page_entry.present or page_entry.available != PAGE_OWNER_USER_PRIVATE) {
            return error.PageNotOwned;
        }

        const offset_in_page: usize = pageOffset(virtual_address);
        const copy_len = @min(source.len - copied, PAGE_SIZE - offset_in_page);
        const physical_page: usize = @as(usize, page_entry.address) << PAGE_SHIFT;
        const destination: [*]u8 = @ptrFromInt(physical_page + offset_in_page);
        @memcpy(destination[0..copy_len], source[copied..][0..copy_len]);
        copied += copy_len;
    }
}

pub fn destroyUserAddressSpace(space: *UserAddressSpace) UserAddressSpaceDestroyError!void {
    if (space.directory == getCurrentPageDirectory()) {
        return error.AddressSpaceActive;
    }

    // Reclaim the complete hierarchy under one allocator lock. Destruction is
    // off-CPU by contract, and avoiding one atomic lock round-trip per user
    // page keeps large address-space retirement bounded by bitmap work alone.
    acquireFrameLock();
    defer releaseFrameLock();

    for (space.directory) |*page_dir_entry| {
        if (!page_dir_entry.present or page_dir_entry.available != TABLE_OWNER_USER_PRIVATE) {
            continue;
        }

        const table_phys: u32 = @as(u32, page_dir_entry.address) << PAGE_SHIFT;
        const table = pageTableFromEntry(page_dir_entry.*);
        for (table) |*page_entry| {
            if (page_entry.present and page_entry.available == PAGE_OWNER_USER_PRIVATE) {
                const page_phys: u32 = @as(u32, page_entry.address) << PAGE_SHIFT;
                physical_frames.release(.{ .base = page_phys, .count = 1 }) catch
                    haltWithMessage("Corrupt owned user-frame accounting!\n");
            }
            page_entry.* = PageTableEntry{};
        }

        physical_frames.release(.{ .base = table_phys, .count = 1 }) catch
            haltWithMessage("Corrupt user page-table accounting!\n");
        page_dir_entry.* = PageTableEntry{};
    }

    const directory_phys: u32 = @intCast(@intFromPtr(space.directory));
    physical_frames.release(.{ .base = directory_phys, .count = 1 }) catch
        haltWithMessage("Corrupt user page-directory accounting!\n");
    space.* = undefined;
}

pub fn switchToUserAddressSpace(space: *const UserAddressSpace) void {
    switchPageDirectory(space.directory);
}

pub fn init() void {
    vga.print("Initializing paging...\n");

    const boot_info = handoff.capturedInfo() orelse
        haltWithMessage("Missing Multiboot memory-map handoff!\n");
    const boot_info_address = handoff.capturedInfoAddress() orelse
        haltWithMessage("Invalid Multiboot information extent!\n");
    const memory_map_bytes = handoff.capturedMemoryMapBytes(boot_info) orelse
        haltWithMessage("Missing Multiboot memory map!\n");
    firmware_memory_map.initializeAllocator(
        MEMORY_SIZE,
        PAGE_SIZE,
        &physical_frames,
        memory_map_bytes,
    ) catch haltWithMessage("Invalid Multiboot memory map!\n");
    firmware_memory_map.reserveLiveHandoffRanges(
        MEMORY_SIZE,
        PAGE_SIZE,
        &physical_frames,
        boot_info_address,
        boot_info,
    ) catch haltWithMessage("Invalid live Multiboot handoff extent!\n");

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
    const reserved_frame_count = (kernel_end + PAGE_SIZE - 1) / PAGE_SIZE;
    physical_frames.reserve(.{
        .base = 0,
        .count = reserved_frame_count,
    }) catch haltWithMessage("Invalid physical-memory reservation!\n");
    if (physical_frames.stats().free == 0) {
        haltWithMessage("No usable physical frames remain after kernel reservation!\n");
    }

    enable_paging(@intFromPtr(&kernel_page_directory));
    unmapBootStackGuardPage();
    // The double-fault task switch loads CR3 from its TSS; point it at the
    // kernel page directory now that paging is live.
    @import("../interrupts/gdt.zig").refreshDoubleFaultCr3();
    vga.print("Paging enabled!\n");
    const stats = frameStats();
    vga.print("Total frames: ");
    numfmt.printDec(stats.total);
    vga.print(" Reserved frames: ");
    numfmt.printDec(stats.reserved);
    vga.print(" Allocated frames: ");
    numfmt.printDec(stats.allocated);
    vga.print("\n");
}

// A boot-stack overflow used to run straight into the device-broker globals
// below stack_bottom and corrupt them silently; Debug builds hit this with
// their larger frames while ReleaseFast masked it. Sacrifice the lowest stack
// page as an unmapped guard so an overflow page-faults at the boundary. Page
// faults fail closed, so the guard stays unmapped for the kernel's lifetime.
fn unmapBootStackGuardPage() void {
    const guard_address: u32 = @intFromPtr(&stack_bottom);
    if (guard_address % PAGE_SIZE != 0) {
        vga.print("Boot stack guard skipped: stack_bottom is not page-aligned\n");
        return;
    }
    _ = unmapBorrowedCurrentPage(guard_address);
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

    const not_present = (regs.err_code & 0x1) == 0;
    const write = (regs.err_code & 0x2) != 0;
    const user = (regs.err_code & 0x4) != 0;
    const reserved = (regs.err_code & 0x8) != 0;
    const instruction_fetch = (regs.err_code & 0x10) != 0;

    const console = @import("../utils/console.zig");
    console.print("\n=== PAGE FAULT ===\n");
    console.print("Address: 0x");
    print_hex_console(faulting_address, console);
    console.print("\n");
    console.print("EIP: 0x");
    print_hex_console(regs.eip, console);
    console.print("\n");

    if (not_present) console.print("  - Page not present\n");
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
