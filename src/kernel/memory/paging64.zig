const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const handoff = @import("../boot/handoff.zig");
const early_console = @import("../utils/console.zig");
const memory = @import("memory.zig");
const numfmt = @import("../utils/numfmt.zig");
const spin = @import("../utils/spin.zig");
const frame_allocator = @import("frame_allocator.zig");
const firmware_memory_map = @import("firmware_memory_map.zig");
const pcid_allocator = @import("pcid_allocator.zig");
const table64 = @import("page_table64.zig");
const virtual_layout = @import("virtual_layout.zig");

const PAGE_SIZE: u32 = virtual_layout.PAGE_BYTES;
const PML4_SHIFT = table64.PML4_SHIFT;
const PDPT_SHIFT = table64.PDPT_SHIFT;
const PAGE_DIRECTORY_SHIFT = table64.PAGE_DIRECTORY_SHIFT;
const PAGE_TABLE_SHIFT = table64.PAGE_TABLE_SHIFT;
const PAGE_OFFSET_MASK: usize = PAGE_SIZE - 1;
const HEX_NIBBLE_BITS = 4;
const HEX_NIBBLE_MASK = 0xF;
const MAX_U32: u32 = ~@as(u32, 0);

pub const PAGE_PRESENT: u32 = 0x1;
pub const PAGE_WRITABLE: u32 = 0x2;
pub const PAGE_USER: u32 = 0x4;
pub const PAGE_WRITE_THROUGH: u32 = 0x8;
pub const PAGE_CACHE_DISABLE: u32 = 0x10;
pub const PAGE_ACCESSED: u32 = 0x20;
pub const PAGE_DIRTY: u32 = 0x40;

pub const PAGE_EXECUTABLE: u32 = 0x200;
pub const CACHES_PROCESS_CONTEXT_MODE = true;
pub const PRECOMPUTES_ADDRESS_SPACE_CR3 = true;
pub const PAGE_TABLE_ACCESS_USES_DIRECT_MAP = true;
pub const OWNED_USER_FRAME_ACCESS_USES_DIRECT_MAP = true;
pub const LOW_IDENTITY_PHYSICAL_LIMIT: frame_allocator.PhysicalAddress = 1024 * 1024 * 1024;
pub const IDENTITY_DMA_ALLOCATION_USES_EXPLICIT_PHYSICAL_LIMIT = true;
pub const GENERAL_ALLOCATION_PREFERS_HIGH_MEMORY = true;
pub const GENERAL_ALLOCATION_CACHES_HIGH_ZONE_AVAILABILITY = true;
pub const DIRECT_MAP_USES_1G_PAGES = true;
pub const PRECISE_IDENTITY_LIMIT_MATCHES_LINKER = true;

const ENTRY_PRESENT = table64.PRESENT;
const ENTRY_WRITABLE = table64.WRITABLE;
const ENTRY_USER = table64.USER;
const ENTRY_WRITE_THROUGH = table64.WRITE_THROUGH;
const ENTRY_CACHE_DISABLE = table64.CACHE_DISABLE;
const ENTRY_LARGE_PAGE = table64.LARGE_PAGE;
const ENTRY_GLOBAL = table64.GLOBAL;

pub const PageTableEntry = table64.Entry;
pub const PageTable = table64.Table;
pub const PageDirectory = PageTable;

pub const FrameRun = frame_allocator.FrameRun;
pub const FrameStats = frame_allocator.Stats;
pub const FrameReleaseError = frame_allocator.Error;

pub const UserAddressSpace = struct {
    directory: *PageDirectory,
    pcid: pcid_allocator.Identifier,
    switch_cr3: usize,
};

pub const UserPermissions = struct {
    writable: bool,
    executable: bool = false,
    write_through: bool = false,
    cache_disabled: bool = false,
};

pub const UserMapError = error{
    OutOfMemory,
    InvalidRange,
    AddressOverflow,
    KernelMappingCollision,
    AlreadyMapped,
    WritableExecutable,
};

pub const UserWriteError = error{
    InvalidRange,
    AddressOverflow,
    PageNotOwned,
};

pub const UserAddressSpaceDestroyError = error{
    AddressSpaceActive,
};

pub const UserAddressSpaceCreateError = error{
    OutOfMemory,
    ProcessContextExhausted,
};

pub const MANAGED_PHYSICAL_BYTES: frame_allocator.PhysicalAddress = 64 * 1024 * 1024 * 1024;
const LARGE_2M_PAGE_SIZE: frame_allocator.PhysicalAddress = 1 << PAGE_DIRECTORY_SHIFT;
const LARGE_1G_PAGE_SIZE: frame_allocator.PhysicalAddress = 1 << PDPT_SHIFT;
const PAGE_DIRECTORY_COVERAGE_BYTES = LARGE_1G_PAGE_SIZE;
const IDENTITY_DIRECTORY_ENTRIES: usize = @intCast(LOW_IDENTITY_PHYSICAL_LIMIT / LARGE_2M_PAGE_SIZE);
pub const DIRECT_MAP_PDPT_ENTRIES: usize = @intCast(MANAGED_PHYSICAL_BYTES / PAGE_DIRECTORY_COVERAGE_BYTES);
pub const DIRECT_MAP_1G_LEAF_COUNT: usize = DIRECT_MAP_PDPT_ENTRIES - 1;
pub const DIRECT_MAP_PAGE_DIRECTORY_COUNT: usize = 1;
// Keep synchronized with __kernel_precise_identity_end in the linker script.
pub const PRECISE_IDENTITY_PAGE_TABLES: usize = 8;
pub const PRECISE_IDENTITY_BYTES: u32 = PRECISE_IDENTITY_PAGE_TABLES * 2 * 1024 * 1024;
const BOOTSTRAP_PAGE_TABLE_COUNT = 5 + 2 * PRECISE_IDENTITY_PAGE_TABLES;

const TABLE_OWNER_INHERITED: u3 = 0;
const TABLE_OWNER_KERNEL_DYNAMIC: u3 = 1;
const TABLE_OWNER_USER_PRIVATE: u3 = 2;
const PAGE_OWNER_BORROWED: u3 = 0;
const PAGE_OWNER_USER_PRIVATE: u3 = 1;

extern var stack_bottom: u8;
extern const __kernel_text_start: u8;
extern const __kernel_text_end: u8;
extern const __kernel_relro_end: u8;
extern const __kernel_precise_identity_end: u8;

const BootstrapPageTables = struct {
    pml4: PageDirectory align(PAGE_SIZE),
    pdpt: PageTable align(PAGE_SIZE),
    page_directory: PageTable align(PAGE_SIZE),
    page_tables: [PRECISE_IDENTITY_PAGE_TABLES]PageTable align(PAGE_SIZE),
    direct_pdpt: PageTable align(PAGE_SIZE),
    direct_page_directory: PageTable align(PAGE_SIZE),
    direct_page_tables: [PRECISE_IDENTITY_PAGE_TABLES]PageTable align(PAGE_SIZE),
};

var bootstrap_page_tables: ?*BootstrapPageTables = null;

const PhysicalFrameAllocator = frame_allocator.Fixed(MANAGED_PHYSICAL_BYTES, PAGE_SIZE);
var physical_frames: PhysicalFrameAllocator = undefined;
var frame_lock = spin.Lock.init();
var high_memory_zone_has_free_frames: bool = false;
var low_identity_frame_cursor = frame_allocator.AllocationCursor{};
var process_contexts = pcid_allocator.Allocator.init();
var process_context_lock = spin.Lock.init();
var process_context_identifiers_enabled: bool = false;

const tableIndex = table64.index;

fn pageOffset(address: usize) usize {
    return address & PAGE_OFFSET_MASK;
}

const entryPresent = table64.isPresent;
const entryOwner = table64.owner;
const entryAddress = table64.address;
const tableEntry = table64.make;

fn leafFlags(flags: u32, global: bool) u64 {
    var result: u64 = ENTRY_PRESENT | table64.NO_EXECUTE;
    if ((flags & PAGE_WRITABLE) != 0) result |= ENTRY_WRITABLE;
    if ((flags & PAGE_USER) != 0) result |= ENTRY_USER;
    if ((flags & PAGE_WRITE_THROUGH) != 0) result |= ENTRY_WRITE_THROUGH;
    if ((flags & PAGE_CACHE_DISABLE) != 0) result |= ENTRY_CACHE_DISABLE;
    if (global) result |= ENTRY_GLOBAL;
    if ((flags & PAGE_EXECUTABLE) != 0) result &= ~table64.NO_EXECUTE;
    return result;
}

const KernelImageExtents = struct {
    text_start: u32,
    text_end: u32,
    immutable_end: u32,
};

fn kernelIdentityLeafFlags(page_address: u32, image: KernelImageExtents) u64 {
    const executable = page_address >= image.text_start and page_address < image.text_end;
    const immutable = page_address >= image.text_start and page_address < image.immutable_end;
    var flags: u64 = ENTRY_PRESENT | ENTRY_GLOBAL;
    if (!immutable) flags |= ENTRY_WRITABLE;
    return table64.withExecutePermission(flags, executable);
}

fn kernelDirectLeafFlags(page_address: u32, image: KernelImageExtents) u64 {
    const immutable = page_address >= image.text_start and page_address < image.immutable_end;
    var flags: u64 = ENTRY_PRESENT | ENTRY_GLOBAL | table64.NO_EXECUTE;
    if (!immutable) flags |= ENTRY_WRITABLE;
    return flags;
}

fn kernelImageExtents() KernelImageExtents {
    const text_start = std.math.cast(u32, @intFromPtr(&__kernel_text_start)) orelse
        haltWithMessage("Kernel text lies outside the low physical aperture!\n");
    const text_end = std.math.cast(u32, @intFromPtr(&__kernel_text_end)) orelse
        haltWithMessage("Kernel text lies outside the low physical aperture!\n");
    const immutable_end = std.math.cast(u32, @intFromPtr(&__kernel_relro_end)) orelse
        haltWithMessage("Kernel immutable image lies outside the low physical aperture!\n");
    const precise_identity_end = std.math.cast(u32, @intFromPtr(&__kernel_precise_identity_end)) orelse
        haltWithMessage("Kernel precise identity limit lies outside the low physical aperture!\n");
    if (text_start % PAGE_SIZE != 0 or
        text_end % PAGE_SIZE != 0 or
        immutable_end % PAGE_SIZE != 0 or
        text_start >= text_end or
        text_end >= immutable_end or
        immutable_end > PRECISE_IDENTITY_BYTES or
        precise_identity_end != PRECISE_IDENTITY_BYTES)
    {
        haltWithMessage("Invalid page-aligned kernel image extents!\n");
    }
    return .{
        .text_start = text_start,
        .text_end = text_end,
        .immutable_end = immutable_end,
    };
}

fn tableFromEntry(entry: PageTableEntry) *PageTable {
    return tableAtPhysical(@intCast(entryAddress(entry)));
}

fn tableAtPhysical(physical_address: frame_allocator.PhysicalAddress) *PageTable {
    return @ptrFromInt(directMapAddress(physical_address) orelse
        haltWithMessage("Page-table frame lies outside the direct-map aperture!\n"));
}

fn bytesAtPhysical(physical_address: frame_allocator.PhysicalAddress) [*]u8 {
    return @ptrFromInt(directMapAddress(physical_address) orelse
        haltWithMessage("Data frame lies outside the direct-map aperture!\n"));
}

fn tablePhysicalAddress(table: *const PageTable) frame_allocator.PhysicalAddress {
    return virtual_layout.directMappedPhysicalAddress(@intFromPtr(table), MANAGED_PHYSICAL_BYTES) orelse
        haltWithMessage("Page-table pointer lies outside the direct-map aperture!\n");
}

fn kernelPageDirectory() *PageDirectory {
    return tableAtPhysical(@intFromPtr(&bootstrapPageTables().pml4));
}

fn bootstrapPageTables() *BootstrapPageTables {
    return bootstrap_page_tables orelse haltWithMessage("Missing bootstrap page-table storage!\n");
}

fn zeroTable(table: *PageTable) void {
    @memset(table, 0);
}

fn acquireFrameLock() void {
    frame_lock.acquire();
}

fn releaseFrameLock() void {
    frame_lock.release();
}

fn acquireProcessContextLock() void {
    process_context_lock.acquire();
}

fn releaseProcessContextLock() void {
    process_context_lock.release();
}

fn tryAllocProcessContext() ?pcid_allocator.Identifier {
    acquireProcessContextLock();
    defer releaseProcessContextLock();
    return process_contexts.allocate();
}

fn releaseProcessContext(identifier: pcid_allocator.Identifier) void {
    acquireProcessContextLock();
    defer releaseProcessContextLock();
    if (process_context_identifiers_enabled) x86.invalidatePcid(identifier);
    process_contexts.release(identifier) catch
        haltWithMessage("Corrupt process-context identifier accounting!\n");
}

fn haltWithMessage(message: []const u8) noreturn {
    early_console.print(message);
    while (true) x86.hlt();
}

inline fn lowIdentityFrameAddress(address: frame_allocator.PhysicalAddress) u32 {
    if (address >= LOW_IDENTITY_PHYSICAL_LIMIT) {
        haltWithMessage("Allocated frame lies outside the low identity aperture!\n");
    }
    return @intCast(address);
}

pub fn directMapAddress(address: frame_allocator.PhysicalAddress) ?usize {
    return virtual_layout.directMappedAddress(address, MANAGED_PHYSICAL_BYTES);
}

pub fn allocGeneralFrame() ?frame_allocator.PhysicalAddress {
    acquireFrameLock();
    defer releaseFrameLock();
    if (high_memory_zone_has_free_frames) {
        if (physical_frames.allocateFrameBetween(LOW_IDENTITY_PHYSICAL_LIMIT, MANAGED_PHYSICAL_BYTES)) |base| {
            return base;
        }
        high_memory_zone_has_free_frames = false;
    }
    return (physical_frames.allocateBelowWithCursor(1, LOW_IDENTITY_PHYSICAL_LIMIT, &low_identity_frame_cursor) orelse return null).base;
}

pub fn allocGeneralFrames(count: u32) ?FrameRun {
    acquireFrameLock();
    defer releaseFrameLock();
    return allocGeneralFramesLocked(count);
}

fn allocGeneralFramesLocked(count: u32) ?FrameRun {
    return allocGeneralRunFrom(
        &physical_frames,
        &high_memory_zone_has_free_frames,
        &low_identity_frame_cursor,
        count,
        LOW_IDENTITY_PHYSICAL_LIMIT,
        MANAGED_PHYSICAL_BYTES,
    );
}

fn allocGeneralRunFrom(
    allocator: anytype,
    high_zone_has_free_frames: *bool,
    low_cursor: *frame_allocator.AllocationCursor,
    count: u32,
    low_identity_limit: frame_allocator.PhysicalAddress,
    managed_bytes: frame_allocator.PhysicalAddress,
) ?FrameRun {
    if (high_zone_has_free_frames.*) {
        if (allocator.allocateBetween(count, low_identity_limit, managed_bytes)) |run| return run;
        if (count == 1) high_zone_has_free_frames.* = false;
    }
    return allocator.allocateBelowWithCursor(count, low_identity_limit, low_cursor);
}

pub fn allocIdentityDmaFrames(count: u32) ?u32 {
    acquireFrameLock();
    defer releaseFrameLock();
    const run = physical_frames.allocateBelowWithCursor(
        count,
        LOW_IDENTITY_PHYSICAL_LIMIT,
        &low_identity_frame_cursor,
    ) orelse return null;
    return lowIdentityFrameAddress(run.base);
}

pub fn releaseIdentityDmaFrames(base: u32, count: u32) FrameReleaseError!void {
    acquireFrameLock();
    defer releaseFrameLock();
    const shared_hint = physical_frames.search_frame_hint;
    defer physical_frames.search_frame_hint = shared_hint;
    try releasePhysicalFramesLocked(base, count);
    low_identity_frame_cursor.next_frame = physical_frames.search_frame_hint;
}

pub fn releaseGeneralFrames(run: FrameRun) FrameReleaseError!void {
    return releasePhysicalFrames(run.base, run.count);
}

pub fn releaseGeneralFrame(base: frame_allocator.PhysicalAddress) FrameReleaseError!void {
    acquireFrameLock();
    defer releaseFrameLock();
    try physical_frames.releaseFrame(base);
    if (base >= LOW_IDENTITY_PHYSICAL_LIMIT) high_memory_zone_has_free_frames = true;
}

fn releasePhysicalFrames(base: frame_allocator.PhysicalAddress, count: u32) FrameReleaseError!void {
    acquireFrameLock();
    defer releaseFrameLock();
    try releasePhysicalFramesLocked(base, count);
}

fn releasePhysicalFramesLocked(base: frame_allocator.PhysicalAddress, count: u32) FrameReleaseError!void {
    try physical_frames.release(.{ .base = base, .count = count });
    if (base >= LOW_IDENTITY_PHYSICAL_LIMIT) high_memory_zone_has_free_frames = true;
}

pub fn frameStats() FrameStats {
    acquireFrameLock();
    defer releaseFrameLock();
    return physical_frames.stats();
}

fn ensureChildTable(
    parent: *PageTable,
    index: usize,
    user: bool,
    owner: u3,
) UserMapError!*PageTable {
    const entry = &parent[index];
    if (!entryPresent(entry.*)) {
        const table_phys = allocGeneralFrame() orelse return error.OutOfMemory;
        const flags = ENTRY_PRESENT | ENTRY_WRITABLE | (if (user) ENTRY_USER else 0);
        entry.* = tableEntry(@intCast(table_phys), flags, owner);
        const table = tableAtPhysical(table_phys);
        zeroTable(table);
        return table;
    }
    if (table64.isLargePage(entry.*)) return error.KernelMappingCollision;

    if (owner == TABLE_OWNER_USER_PRIVATE and entryOwner(entry.*) != TABLE_OWNER_USER_PRIVATE) {
        return error.KernelMappingCollision;
    }
    if (user and (entry.* & ENTRY_USER) == 0) {
        if (entryOwner(entry.*) != TABLE_OWNER_USER_PRIVATE) {
            return error.KernelMappingCollision;
        }
        entry.* |= ENTRY_USER;
    }
    entry.* |= ENTRY_WRITABLE;
    return tableFromEntry(entry.*);
}

fn mapBorrowedPageIn(
    pml4: *PageDirectory,
    virt_addr: usize,
    phys_addr: usize,
    flags: u32,
    table_owner: u3,
    global: bool,
) UserMapError!void {
    if (pageOffset(virt_addr) != 0 or pageOffset(phys_addr) != 0) {
        return error.InvalidRange;
    }

    const user = (flags & PAGE_USER) != 0;
    const pdpt = try ensureChildTable(pml4, tableIndex(virt_addr, PML4_SHIFT), user, table_owner);
    const page_directory = try ensureChildTable(pdpt, tableIndex(virt_addr, PDPT_SHIFT), user, table_owner);
    const page_table = try ensureChildTable(page_directory, tableIndex(virt_addr, PAGE_DIRECTORY_SHIFT), user, table_owner);
    const page_entry = &page_table[tableIndex(virt_addr, PAGE_TABLE_SHIFT)];
    if (entryPresent(page_entry.*) and entryOwner(page_entry.*) == PAGE_OWNER_USER_PRIVATE) {
        return error.AlreadyMapped;
    }

    page_entry.* = tableEntry(phys_addr, leafFlags(flags, global), PAGE_OWNER_BORROWED);
    if (global or pml4 == getCurrentPageDirectory()) invalidate_page(virt_addr);
}

fn mapFailure(error_value: UserMapError) noreturn {
    switch (error_value) {
        error.OutOfMemory => haltWithMessage("Out of physical memory while mapping page!\n"),
        error.InvalidRange => haltWithMessage("Attempted to map an unaligned page!\n"),
        error.KernelMappingCollision => haltWithMessage("User mapping collided with inherited kernel memory!\n"),
        error.AlreadyMapped => haltWithMessage("Attempted to replace an owned user page!\n"),
        error.WritableExecutable => haltWithMessage("Attempted to create a writable executable user page!\n"),
        error.AddressOverflow => haltWithMessage("Page mapping address overflow!\n"),
    }
}

pub fn mapKernelBorrowedPage(virt_addr: usize, phys_addr: usize, flags: u32) void {
    if (!table64.isCanonicalVirtualAddress(virt_addr))
        haltWithMessage("Kernel mapping uses a non-canonical virtual address!\n");
    if (!table64.physicalAddressFits(phys_addr))
        haltWithMessage("Kernel physical mapping exceeds the x86-64 address width!\n");
    mapBorrowedPageIn(
        kernelPageDirectory(),
        virt_addr,
        phys_addr,
        flags & ~PAGE_USER,
        TABLE_OWNER_KERNEL_DYNAMIC,
        true,
    ) catch |err| mapFailure(err);
}

fn lookupLeaf(pml4: *PageDirectory, virt_addr: usize) ?*PageTableEntry {
    const pml4_entry = pml4[tableIndex(virt_addr, PML4_SHIFT)];
    if (!entryPresent(pml4_entry)) return null;
    const pdpt = tableFromEntry(pml4_entry);
    const pdpt_entry = &pdpt[tableIndex(virt_addr, PDPT_SHIFT)];
    if (!entryPresent(pdpt_entry.*)) return null;
    if (table64.isLargePage(pdpt_entry.*)) return pdpt_entry;
    const page_directory = tableFromEntry(pdpt_entry.*);
    const directory_entry = &page_directory[tableIndex(virt_addr, PAGE_DIRECTORY_SHIFT)];
    if (!entryPresent(directory_entry.*)) return null;
    if (table64.isLargePage(directory_entry.*)) return directory_entry;
    const page_table = tableFromEntry(directory_entry.*);
    return &page_table[tableIndex(virt_addr, PAGE_TABLE_SHIFT)];
}

pub fn setPageReadOnly(virt_addr: usize) void {
    const entry = lookupLeaf(getCurrentPageDirectory(), virt_addr) orelse return;
    if (!entryPresent(entry.*) or table64.isLargePage(entry.*)) return;
    entry.* &= ~ENTRY_WRITABLE;
    invalidate_page(virt_addr);
}

pub const PagePermissions = struct {
    writable: bool,
    executable: bool,
    user: bool,
};

pub fn currentPagePermissions(virt_addr: usize) ?PagePermissions {
    const entry = lookupLeaf(getCurrentPageDirectory(), virt_addr) orelse return null;
    if (!entryPresent(entry.*)) return null;
    return .{
        .writable = (entry.* & ENTRY_WRITABLE) != 0,
        .executable = table64.isExecutable(entry.*),
        .user = (entry.* & ENTRY_USER) != 0,
    };
}

pub fn enableWriteProtect() void {
    x86.writeCr0(x86.readCr0() | x86.CR0_WP);
}

pub fn unmapBorrowedCurrentPage(virt_addr: usize) bool {
    const entry = lookupLeaf(getCurrentPageDirectory(), virt_addr) orelse return false;
    if (!entryPresent(entry.*) or
        table64.isLargePage(entry.*) or
        entryOwner(entry.*) != PAGE_OWNER_BORROWED)
    {
        return false;
    }
    entry.* = 0;
    invalidate_page(virt_addr);
    return true;
}

pub fn createUserAddressSpace() UserAddressSpaceCreateError!UserAddressSpace {
    const pml4_phys = allocGeneralFrame() orelse return error.OutOfMemory;
    const pml4 = tableAtPhysical(pml4_phys);
    zeroTable(pml4);

    const pdpt_phys = allocGeneralFrame() orelse {
        releasePhysicalFrames(pml4_phys, 1) catch haltWithMessage("Corrupt PML4 allocation accounting!\n");
        return error.OutOfMemory;
    };
    const pdpt = tableAtPhysical(pdpt_phys);
    zeroTable(pdpt);
    for (tableAtPhysical(@intFromPtr(&bootstrapPageTables().pdpt)), pdpt) |kernel_entry, *user_entry| {
        if (entryPresent(kernel_entry)) user_entry.* = kernel_entry;
    }

    for (kernelPageDirectory()[1..], pml4[1..]) |kernel_entry, *user_entry| {
        if (entryPresent(kernel_entry)) user_entry.* = kernel_entry;
    }

    pml4[0] = tableEntry(@intCast(pdpt_phys), ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER, TABLE_OWNER_USER_PRIVATE);
    const pcid = tryAllocProcessContext() orelse {
        releasePhysicalFrames(pdpt_phys, 1) catch haltWithMessage("Corrupt user PDPT accounting!\n");
        releasePhysicalFrames(pml4_phys, 1) catch haltWithMessage("Corrupt PML4 allocation accounting!\n");
        return error.ProcessContextExhausted;
    };
    return .{
        .directory = pml4,
        .pcid = pcid,
        .switch_cr3 = addressSpaceCr3(pml4_phys, pcid),
    };
}

fn ensureOwnedLeaf(space: *UserAddressSpace, virtual_address: u32) UserMapError!*PageTableEntry {
    const address: usize = virtual_address;
    const pdpt = try ensureChildTable(space.directory, tableIndex(address, PML4_SHIFT), true, TABLE_OWNER_USER_PRIVATE);
    const page_directory = try ensureChildTable(pdpt, tableIndex(address, PDPT_SHIFT), true, TABLE_OWNER_USER_PRIVATE);
    const page_table = try ensureChildTable(page_directory, tableIndex(address, PAGE_DIRECTORY_SHIFT), true, TABLE_OWNER_USER_PRIVATE);
    return &page_table[tableIndex(address, PAGE_TABLE_SHIFT)];
}

fn validateOwnedMappingSlot(space: *const UserAddressSpace, virtual_address: u32) UserMapError!void {
    const address: usize = virtual_address;
    const pml4_entry = space.directory[tableIndex(address, PML4_SHIFT)];
    if (!entryPresent(pml4_entry)) return;
    if (entryOwner(pml4_entry) != TABLE_OWNER_USER_PRIVATE) return error.KernelMappingCollision;

    const pdpt = tableFromEntry(pml4_entry);
    const pdpt_entry = pdpt[tableIndex(address, PDPT_SHIFT)];
    if (!entryPresent(pdpt_entry)) return;
    if (entryOwner(pdpt_entry) != TABLE_OWNER_USER_PRIVATE) return error.KernelMappingCollision;

    const page_directory = tableFromEntry(pdpt_entry);
    const directory_entry = page_directory[tableIndex(address, PAGE_DIRECTORY_SHIFT)];
    if (!entryPresent(directory_entry)) return;
    if (entryOwner(directory_entry) != TABLE_OWNER_USER_PRIVATE) return error.KernelMappingCollision;

    const page_table = tableFromEntry(directory_entry);
    if (entryPresent(page_table[tableIndex(address, PAGE_TABLE_SHIFT)])) return error.AlreadyMapped;
}

pub fn mapOwnedUserRange(
    space: *UserAddressSpace,
    virtual_start: u32,
    size_bytes: u32,
    permissions: UserPermissions,
) UserMapError!void {
    if (pageOffset(virtual_start) != 0 or size_bytes == 0) return error.InvalidRange;
    if (permissions.writable and permissions.executable) return error.WritableExecutable;
    if (size_bytes > MAX_U32 - (PAGE_SIZE - 1)) return error.AddressOverflow;

    const mapped_size = (size_bytes + PAGE_SIZE - 1) & ~PAGE_OFFSET_MASK;
    if (virtual_start > MAX_U32 - mapped_size) return error.AddressOverflow;

    var offset: u32 = 0;
    while (offset < mapped_size) : (offset += PAGE_SIZE) {
        try validateOwnedMappingSlot(space, virtual_start + offset);
    }

    offset = 0;
    while (offset < mapped_size) : (offset += PAGE_SIZE) {
        const virtual_address = virtual_start + offset;
        const page_entry = try ensureOwnedLeaf(space, virtual_address);
        if (entryPresent(page_entry.*)) return error.AlreadyMapped;

        const page_phys = allocGeneralFrame() orelse return error.OutOfMemory;
        const kernel_alias = bytesAtPhysical(page_phys);
        @memset(kernel_alias[0..PAGE_SIZE], 0);
        var flags: u32 = PAGE_PRESENT | PAGE_USER;
        if (permissions.writable) flags |= PAGE_WRITABLE;
        if (permissions.write_through) flags |= PAGE_WRITE_THROUGH;
        if (permissions.cache_disabled) flags |= PAGE_CACHE_DISABLE;
        const entry_flags = table64.withExecutePermission(leafFlags(flags, false), permissions.executable);
        page_entry.* = tableEntry(@intCast(page_phys), entry_flags, PAGE_OWNER_USER_PRIVATE);
    }
}

pub fn ownedUserPageIsExecutable(space: *const UserAddressSpace, virtual_address: u32) ?bool {
    const entry = lookupLeaf(space.directory, virtual_address) orelse return null;
    if (!entryPresent(entry.*) or entryOwner(entry.*) != PAGE_OWNER_USER_PRIVATE) return null;
    if ((entry.* & ENTRY_USER) == 0) return null;
    return table64.isExecutable(entry.*);
}

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
        const entry = lookupLeaf(space.directory, virtual_address) orelse return error.PageNotOwned;
        if (!entryPresent(entry.*) or entryOwner(entry.*) != PAGE_OWNER_USER_PRIVATE) {
            return error.PageNotOwned;
        }

        const offset_in_page: usize = virtual_address & PAGE_OFFSET_MASK;
        const copy_len = @min(source.len - copied, PAGE_SIZE - offset_in_page);
        const destination = bytesAtPhysical(@intCast(entryAddress(entry.*))) + offset_in_page;
        @memcpy(destination[0..copy_len], source[copied..][0..copy_len]);
        copied += copy_len;
    }
}

fn releaseOwnedHierarchy(pml4: *PageDirectory) void {
    for (pml4) |*pml4_entry| {
        if (!entryPresent(pml4_entry.*) or entryOwner(pml4_entry.*) != TABLE_OWNER_USER_PRIVATE) continue;
        const pdpt_phys: frame_allocator.PhysicalAddress = @intCast(entryAddress(pml4_entry.*));
        const pdpt = tableFromEntry(pml4_entry.*);
        for (pdpt) |*pdpt_entry| {
            if (!entryPresent(pdpt_entry.*) or entryOwner(pdpt_entry.*) != TABLE_OWNER_USER_PRIVATE) continue;
            const page_directory_phys: frame_allocator.PhysicalAddress = @intCast(entryAddress(pdpt_entry.*));
            const page_directory = tableFromEntry(pdpt_entry.*);
            for (page_directory) |*directory_entry| {
                if (!entryPresent(directory_entry.*) or entryOwner(directory_entry.*) != TABLE_OWNER_USER_PRIVATE) continue;
                const page_table_phys: frame_allocator.PhysicalAddress = @intCast(entryAddress(directory_entry.*));
                const page_table = tableFromEntry(directory_entry.*);
                for (page_table) |*page_entry| {
                    if (entryPresent(page_entry.*) and entryOwner(page_entry.*) == PAGE_OWNER_USER_PRIVATE) {
                        releasePhysicalFramesLocked(@intCast(entryAddress(page_entry.*)), 1) catch
                            haltWithMessage("Corrupt owned user-frame accounting!\n");
                    }
                    page_entry.* = 0;
                }
                releasePhysicalFramesLocked(page_table_phys, 1) catch
                    haltWithMessage("Corrupt user page-table accounting!\n");
                directory_entry.* = 0;
            }
            releasePhysicalFramesLocked(page_directory_phys, 1) catch
                haltWithMessage("Corrupt user page-directory accounting!\n");
            pdpt_entry.* = 0;
        }
        releasePhysicalFramesLocked(pdpt_phys, 1) catch
            haltWithMessage("Corrupt user PDPT accounting!\n");
        pml4_entry.* = 0;
    }
}

pub fn destroyUserAddressSpace(space: *UserAddressSpace) UserAddressSpaceDestroyError!void {
    if (space.directory == getCurrentPageDirectory()) return error.AddressSpaceActive;

    acquireFrameLock();
    releaseOwnedHierarchy(space.directory);
    releasePhysicalFramesLocked(tablePhysicalAddress(space.directory), 1) catch
        haltWithMessage("Corrupt user PML4 accounting!\n");
    releaseFrameLock();
    releaseProcessContext(space.pcid);
    space.* = undefined;
}

pub fn switchToUserAddressSpace(space: *const UserAddressSpace) void {
    switchAddressSpace(space.directory, space.switch_cr3);
}

pub fn switchToKernelAddressSpace() void {
    switchAddressSpace(kernelPageDirectory(), kernel_switch_cr3);
}

fn initializeKernelHierarchy() void {
    const tables = bootstrapPageTables();
    zeroTable(&tables.pml4);
    zeroTable(&tables.pdpt);
    zeroTable(&tables.page_directory);
    zeroTable(&tables.direct_pdpt);
    zeroTable(&tables.direct_page_directory);

    tables.pml4[0] = tableEntry(@intFromPtr(&tables.pdpt), ENTRY_PRESENT | ENTRY_WRITABLE, TABLE_OWNER_INHERITED);
    tables.pdpt[0] = tableEntry(@intFromPtr(&tables.page_directory), ENTRY_PRESENT | ENTRY_WRITABLE, TABLE_OWNER_INHERITED);
    tables.pml4[tableIndex(virtual_layout.physical_memory.base, PML4_SHIFT)] = tableEntry(
        @intFromPtr(&tables.direct_pdpt),
        ENTRY_PRESENT | ENTRY_WRITABLE,
        TABLE_OWNER_INHERITED,
    );
    tables.direct_pdpt[0] = tableEntry(
        @intFromPtr(&tables.direct_page_directory),
        ENTRY_PRESENT | ENTRY_WRITABLE,
        TABLE_OWNER_INHERITED,
    );

    const image = kernelImageExtents();
    var identity_physical_address: u32 = 0;
    for (&tables.page_tables, 0..) |*page_table, table_index| {
        zeroTable(page_table);
        for (page_table) |*entry| {
            entry.* = tableEntry(
                identity_physical_address,
                kernelIdentityLeafFlags(identity_physical_address, image),
                PAGE_OWNER_BORROWED,
            );
            identity_physical_address += PAGE_SIZE;
        }
        tables.page_directory[table_index] = tableEntry(
            @intFromPtr(page_table),
            ENTRY_PRESENT | ENTRY_WRITABLE,
            TABLE_OWNER_INHERITED,
        );
    }

    var directory_index: usize = tables.page_tables.len;
    while (directory_index < IDENTITY_DIRECTORY_ENTRIES) : (directory_index += 1) {
        tables.page_directory[directory_index] = large2MiBPhysicalEntry(identity_physical_address);
        identity_physical_address += @intCast(LARGE_2M_PAGE_SIZE);
    }

    var direct_physical_address: frame_allocator.PhysicalAddress = 0;
    for (&tables.direct_page_tables, 0..) |*page_table, table_index| {
        zeroTable(page_table);
        for (page_table) |*entry| {
            entry.* = tableEntry(
                @intCast(direct_physical_address),
                kernelDirectLeafFlags(@intCast(direct_physical_address), image),
                PAGE_OWNER_BORROWED,
            );
            direct_physical_address += PAGE_SIZE;
        }
        tables.direct_page_directory[table_index] = tableEntry(
            @intFromPtr(page_table),
            ENTRY_PRESENT | ENTRY_WRITABLE,
            TABLE_OWNER_INHERITED,
        );
    }

    directory_index = tables.direct_page_tables.len;
    while (directory_index < table64.TABLE_ENTRIES) : (directory_index += 1) {
        tables.direct_page_directory[directory_index] = large2MiBPhysicalEntry(direct_physical_address);
        direct_physical_address += LARGE_2M_PAGE_SIZE;
    }
    for (tables.direct_pdpt[1..DIRECT_MAP_PDPT_ENTRIES]) |*entry| {
        entry.* = large1GiBPhysicalEntry(direct_physical_address);
        direct_physical_address += LARGE_1G_PAGE_SIZE;
    }
}

fn large2MiBPhysicalEntry(physical_address: frame_allocator.PhysicalAddress) PageTableEntry {
    return largePhysicalEntry(physical_address);
}

fn large1GiBPhysicalEntry(physical_address: frame_allocator.PhysicalAddress) PageTableEntry {
    return largePhysicalEntry(physical_address);
}

fn largePhysicalEntry(physical_address: frame_allocator.PhysicalAddress) PageTableEntry {
    return tableEntry(
        @intCast(physical_address),
        ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_LARGE_PAGE | ENTRY_GLOBAL | table64.NO_EXECUTE,
        PAGE_OWNER_BORROWED,
    );
}

fn validateHighMemoryDirectMap() bool {
    acquireFrameLock();
    const run = physical_frames.allocateBetween(1, LOW_IDENTITY_PHYSICAL_LIMIT, MANAGED_PHYSICAL_BYTES) orelse {
        releaseFrameLock();
        return false;
    };
    releaseFrameLock();
    defer releasePhysicalFrames(run.base, 1) catch
        haltWithMessage("Corrupt high-memory probe accounting!\n");

    const direct_alias = directMapAddress(run.base) orelse
        haltWithMessage("High-memory probe lies outside the direct-map aperture!\n");
    const permissions = currentPagePermissions(direct_alias) orelse
        haltWithMessage("High-memory direct-map leaf is missing!\n");
    if (!permissions.writable or permissions.executable or permissions.user) {
        haltWithMessage("High-memory direct-map permissions are invalid!\n");
    }
    const probe: *volatile u8 = @ptrFromInt(direct_alias);
    const previous = probe.*;
    const pattern = previous ^ 0xA5;
    probe.* = pattern;
    if (probe.* != pattern) haltWithMessage("High-memory direct-map probe failed!\n");
    probe.* = previous;
    return true;
}

pub fn init() void {
    early_console.print("Initializing four-level paging...\n");

    const boot_info = handoff.capturedInfo() orelse
        haltWithMessage("Missing Multiboot memory-map handoff!\n");
    const boot_info_address = handoff.capturedInfoAddress() orelse
        haltWithMessage("Invalid Multiboot information extent!\n");
    const memory_map = handoff.capturedMemoryMap(boot_info) orelse
        haltWithMessage("Missing Multiboot memory map!\n");
    const bootstrap_tables_memory = memory.claimEarly(
        @sizeOf(BootstrapPageTables),
        @alignOf(BootstrapPageTables),
    ) orelse haltWithMessage("Insufficient early heap for bootstrap page tables!\n");
    bootstrap_page_tables = @ptrCast(@alignCast(bootstrap_tables_memory));
    const frame_storage_memory = memory.claimEarly(
        PhysicalFrameAllocator.storage_bytes,
        @alignOf(PhysicalFrameAllocator.Storage),
    ) orelse haltWithMessage("Insufficient early heap for physical-frame state!\n");
    const frame_storage: *PhysicalFrameAllocator.Storage = @ptrCast(@alignCast(frame_storage_memory));
    physical_frames = PhysicalFrameAllocator.bindStorage(frame_storage);
    firmware_memory_map.initializeAllocator(MANAGED_PHYSICAL_BYTES, PAGE_SIZE, &physical_frames, memory_map) catch
        haltWithMessage("Invalid Multiboot memory map!\n");
    high_memory_zone_has_free_frames = false;
    low_identity_frame_cursor = .{};
    firmware_memory_map.reserveLiveHandoffRanges(
        MANAGED_PHYSICAL_BYTES,
        PAGE_SIZE,
        &physical_frames,
        boot_info_address,
        boot_info,
    ) catch haltWithMessage("Invalid live Multiboot handoff extent!\n");

    initializeKernelHierarchy();

    const kernel_end = memory.getReservedMemoryEnd();
    const reserved_end = std.math.add(usize, kernel_end, PAGE_SIZE - 1) catch
        haltWithMessage("Kernel reserved-memory extent overflow!\n");
    const reserved_frame_count = std.math.cast(u32, reserved_end / PAGE_SIZE) orelse
        haltWithMessage("Kernel reserved-memory extent exceeds the managed physical aperture!\n");
    physical_frames.reserve(.{ .base = 0, .count = reserved_frame_count }) catch
        haltWithMessage("Invalid physical-memory reservation!\n");
    physical_frames.sealReservations() catch
        haltWithMessage("Physical-memory reservation table overflow!\n");
    if (physical_frames.stats().free == 0) {
        haltWithMessage("No usable physical frames remain after kernel reservation!\n");
    }

    enableWriteProtect();
    process_context_identifiers_enabled = x86.processContextIdentifiersEnabled();
    const kernel_pml4_physical = @intFromPtr(&bootstrapPageTables().pml4);
    x86.writeCr3(kernel_pml4_physical);
    current_page_directory = kernelPageDirectory();
    kernel_switch_cr3 = addressSpaceCr3(kernel_pml4_physical, pcid_allocator.KERNEL_IDENTIFIER);
    if (validateHighMemoryDirectMap()) {
        early_console.print("High-memory direct map: online\n");
    }
    unmapBootStackGuardPage();
    early_console.print("Four-level paging enabled!\n");
    const stats = frameStats();
    early_console.print("Total frames: ");
    numfmt.printDec(stats.total);
    early_console.print(" Reserved frames: ");
    numfmt.printDec(stats.reserved);
    early_console.print(" Allocated frames: ");
    numfmt.printDec(stats.allocated);
    early_console.print("\n");
}

fn unmapBootStackGuardPage() void {
    const guard_address = @intFromPtr(&stack_bottom);
    if (guard_address % PAGE_SIZE != 0) {
        early_console.print("Boot stack guard skipped: stack_bottom is not page-aligned\n");
        return;
    }
    _ = unmapBorrowedCurrentPage(guard_address);
}

pub fn page_fault_handler(regs: *const @import("../interrupts/isr.zig").Registers) void {
    const faulting_address = x86.readCr2();
    const not_present = (regs.err_code & 0x1) == 0;
    const write = (regs.err_code & 0x2) != 0;
    const user = (regs.err_code & 0x4) != 0;
    const reserved = (regs.err_code & 0x8) != 0;
    const instruction_fetch = (regs.err_code & 0x10) != 0;

    const console = @import("../utils/console.zig");
    console.print("\n=== PAGE FAULT ===\n");
    console.print("Address: 0x");
    printHex(faulting_address, console);
    console.print("\nInstruction: 0x");
    printHex(regs.eip, console);
    console.print("\n");
    if (not_present) console.print("  - Page not present\n");
    if (write) console.print("  - Write violation\n") else console.print("  - Read violation\n");
    if (user) console.print("  - User mode\n") else console.print("  - Kernel mode\n");
    if (reserved) console.print("  - Reserved bit violation\n");
    if (instruction_fetch) console.print("  - Instruction fetch\n");

    const panic_utils = @import("../utils/panic.zig");
    panic_utils.panic("unrecoverable page fault at 0x{x} (instruction=0x{x})", .{ faulting_address, regs.eip });
}

fn printHex(value: anytype, console: anytype) void {
    const hex_chars = "0123456789ABCDEF";
    var shift: usize = @bitSizeOf(@TypeOf(value)) - HEX_NIBBLE_BITS;
    while (true) : (shift -= HEX_NIBBLE_BITS) {
        const nibble: usize = @intCast((value >> @intCast(shift)) & HEX_NIBBLE_MASK);
        console.printChar(hex_chars[nibble]);
        if (shift == 0) break;
    }
}

var current_page_directory: *PageDirectory = undefined;
var kernel_switch_cr3: usize = 0;

pub fn getCurrentPageDirectory() *PageDirectory {
    return current_page_directory;
}

fn addressSpaceCr3(directory_physical: frame_allocator.PhysicalAddress, pcid: pcid_allocator.Identifier) usize {
    const cr3_base = std.math.cast(usize, directory_physical) orelse
        haltWithMessage("Address-space root exceeds the machine address width!\n");
    if (!process_context_identifiers_enabled) return cr3_base;
    return x86.pcidCr3Value(cr3_base, pcid, true) orelse
        haltWithMessage("Invalid address-space CR3 value!\n");
}

fn switchAddressSpace(directory: *PageDirectory, switch_cr3: usize) void {
    if (directory == current_page_directory) return;
    x86.writeCr3(switch_cr3);
    current_page_directory = directory;
}

fn invalidate_page(virt_addr: usize) void {
    x86.invalidatePage(virt_addr);
}

comptime {
    if (MANAGED_PHYSICAL_BYTES % LARGE_1G_PAGE_SIZE != 0) {
        @compileError("the managed physical aperture must be page-directory aligned");
    }
    if (IDENTITY_DIRECTORY_ENTRIES != table64.TABLE_ENTRIES) {
        @compileError("the low identity aperture must fill one page directory");
    }
    if (DIRECT_MAP_PDPT_ENTRIES == 0 or DIRECT_MAP_PDPT_ENTRIES > table64.TABLE_ENTRIES) {
        @compileError("the direct-map aperture must fit one page-directory-pointer table");
    }
    if (LOW_IDENTITY_PHYSICAL_LIMIT != LARGE_1G_PAGE_SIZE) {
        @compileError("the low identity aperture must occupy exactly one page directory");
    }
    if (PRECISE_IDENTITY_BYTES != 16 * 1024 * 1024) {
        @compileError("the precise identity region must cover the first 16 MiB");
    }
    if (@sizeOf(BootstrapPageTables) != BOOTSTRAP_PAGE_TABLE_COUNT * PAGE_SIZE or
        @alignOf(BootstrapPageTables) != PAGE_SIZE)
    {
        @compileError("bootstrap page-table storage must occupy whole page-aligned frames");
    }
    if (MANAGED_PHYSICAL_BYTES > virtual_layout.PHYSICAL_WINDOW_CAPACITY_BYTES) {
        @compileError("the managed physical aperture exceeds the direct-map window");
    }
    if (tableIndex(virtual_layout.physical_memory.base, PML4_SHIFT) == 0 or
        tableIndex(virtual_layout.physical_memory.base, PDPT_SHIFT) != 0)
    {
        @compileError("the direct-map window must begin at an isolated PML4 slot");
    }
}

test "large physical leaves are writable global and non-executable" {
    const physical_address: frame_allocator.PhysicalAddress = 8 * 1024 * 1024;
    const entry = large2MiBPhysicalEntry(physical_address);
    try std.testing.expectEqual(@as(usize, physical_address), entryAddress(entry));
    try std.testing.expect(table64.isLargePage(entry));
    try std.testing.expect((entry & ENTRY_WRITABLE) != 0);
    try std.testing.expect((entry & ENTRY_GLOBAL) != 0);
    try std.testing.expect(!table64.isExecutable(entry));
}

test "one GiB direct leaves preserve aligned high physical addresses" {
    const physical_address: frame_allocator.PhysicalAddress = 4 * 1024 * 1024 * 1024;
    const entry = large1GiBPhysicalEntry(physical_address);
    try std.testing.expectEqual(@as(usize, physical_address), entryAddress(entry));
    try std.testing.expect(table64.isLargePage(entry));
    try std.testing.expect((entry & ENTRY_GLOBAL) != 0);
    try std.testing.expect(!table64.isExecutable(entry));
}

test "kernel identity mapping executes only the linker-bounded text pages" {
    const image = KernelImageExtents{
        .text_start = 0x10_0000,
        .text_end = 0x12_0000,
        .immutable_end = 0x18_0000,
    };

    const low_memory = kernelIdentityLeafFlags(0, image);
    try std.testing.expect((low_memory & ENTRY_GLOBAL) != 0);
    try std.testing.expect((low_memory & ENTRY_WRITABLE) != 0);
    try std.testing.expect(!table64.isExecutable(low_memory));

    const text = kernelIdentityLeafFlags(image.text_start, image);
    try std.testing.expect((text & ENTRY_WRITABLE) == 0);
    try std.testing.expect(table64.isExecutable(text));

    const immutable_data = kernelIdentityLeafFlags(image.text_end, image);
    try std.testing.expect((immutable_data & ENTRY_WRITABLE) == 0);
    try std.testing.expect(!table64.isExecutable(immutable_data));

    const mutable_data = kernelIdentityLeafFlags(image.immutable_end, image);
    try std.testing.expect((mutable_data & ENTRY_WRITABLE) != 0);
    try std.testing.expect(!table64.isExecutable(mutable_data));
}

test "precise identity mapping retains verification image headroom" {
    try std.testing.expect(PRECISE_IDENTITY_LIMIT_MATCHES_LINKER);
    try std.testing.expectEqual(@as(usize, 8), PRECISE_IDENTITY_PAGE_TABLES);
    try std.testing.expectEqual(@as(u32, 16 * 1024 * 1024), PRECISE_IDENTITY_BYTES);
}

test "kernel direct mapping is non-executable and preserves image immutability" {
    const image = KernelImageExtents{
        .text_start = 0x10_0000,
        .text_end = 0x12_0000,
        .immutable_end = 0x18_0000,
    };

    const text_alias = kernelDirectLeafFlags(image.text_start, image);
    try std.testing.expect((text_alias & ENTRY_WRITABLE) == 0);
    try std.testing.expect(!table64.isExecutable(text_alias));

    const immutable_alias = kernelDirectLeafFlags(image.text_end, image);
    try std.testing.expect((immutable_alias & ENTRY_WRITABLE) == 0);
    try std.testing.expect(!table64.isExecutable(immutable_alias));

    const mutable_alias = kernelDirectLeafFlags(image.immutable_end, image);
    try std.testing.expect((mutable_alias & ENTRY_WRITABLE) != 0);
    try std.testing.expect(!table64.isExecutable(mutable_alias));
}

test "direct physical aliases cover only the managed aperture" {
    try std.testing.expectEqual(virtual_layout.physical_memory.base, directMapAddress(0).?);
    try std.testing.expectEqual(
        virtual_layout.physical_memory.base + @as(usize, @intCast(MANAGED_PHYSICAL_BYTES - 1)),
        directMapAddress(MANAGED_PHYSICAL_BYTES - 1).?,
    );
    try std.testing.expect(directMapAddress(MANAGED_PHYSICAL_BYTES) == null);
}

test "general contiguous allocation prefers high memory" {
    const test_frame_count = 8;
    const low_frame_count = 4;
    const managed_bytes = test_frame_count * PAGE_SIZE;
    const low_identity_limit = low_frame_count * PAGE_SIZE;
    const TestAllocator = frame_allocator.Fixed(managed_bytes, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    var high_zone_has_free_frames = true;
    var low_cursor = frame_allocator.AllocationCursor{};

    const run = allocGeneralRunFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        2,
        low_identity_limit,
        managed_bytes,
    ).?;
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, low_identity_limit), run.base);
    try std.testing.expectEqual(@as(u32, 2), run.count);
    try std.testing.expect(high_zone_has_free_frames);
}

test "general allocation progress survives low-memory allocation activity" {
    const test_frame_count = 12;
    const low_frame_count = 4;
    const managed_bytes = test_frame_count * PAGE_SIZE;
    const low_identity_limit = low_frame_count * PAGE_SIZE;
    const TestAllocator = frame_allocator.Fixed(managed_bytes, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    var high_zone_has_free_frames = true;
    var low_cursor = frame_allocator.AllocationCursor{};

    const first_high = allocGeneralRunFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        1,
        low_identity_limit,
        managed_bytes,
    ).?;
    const first_low = allocator.allocateBelowWithCursor(1, low_identity_limit, &low_cursor).?;
    const second_high = allocGeneralRunFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        1,
        low_identity_limit,
        managed_bytes,
    ).?;

    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, low_identity_limit), first_high.base);
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, 0), first_low.base);
    try std.testing.expectEqual(
        @as(frame_allocator.PhysicalAddress, low_identity_limit + PAGE_SIZE),
        second_high.base,
    );
}

test "general contiguous allocation preserves the high-memory availability hint across fragmentation" {
    const test_frame_count = 8;
    const low_frame_count = 4;
    const managed_bytes = test_frame_count * PAGE_SIZE;
    const low_identity_limit = low_frame_count * PAGE_SIZE;
    const TestAllocator = frame_allocator.Fixed(managed_bytes, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    try allocator.reserve(.{ .base = 4 * PAGE_SIZE, .count = 1 });
    try allocator.reserve(.{ .base = 6 * PAGE_SIZE, .count = 1 });
    var high_zone_has_free_frames = true;
    var low_cursor = frame_allocator.AllocationCursor{};

    const run = allocGeneralRunFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        2,
        low_identity_limit,
        managed_bytes,
    ).?;
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, 0), run.base);
    try std.testing.expect(high_zone_has_free_frames);
}

test "general single-frame allocation caches an exhausted high zone" {
    const test_frame_count = 8;
    const low_frame_count = 4;
    const managed_bytes = test_frame_count * PAGE_SIZE;
    const low_identity_limit = low_frame_count * PAGE_SIZE;
    const TestAllocator = frame_allocator.Fixed(managed_bytes, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    try allocator.reserve(.{ .base = low_identity_limit, .count = test_frame_count - low_frame_count });
    var high_zone_has_free_frames = true;
    var low_cursor = frame_allocator.AllocationCursor{};

    const run = allocGeneralRunFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        1,
        low_identity_limit,
        managed_bytes,
    ).?;
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, 0), run.base);
    try std.testing.expect(!high_zone_has_free_frames);
}

test "direct hierarchy covers the full 64 GiB physical aperture" {
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, 64 * 1024 * 1024 * 1024), MANAGED_PHYSICAL_BYTES);
    try std.testing.expectEqual(@as(usize, 64), DIRECT_MAP_PDPT_ENTRIES);
    try std.testing.expectEqual(@as(usize, 63), DIRECT_MAP_1G_LEAF_COUNT);
    try std.testing.expectEqual(@as(usize, 1), DIRECT_MAP_PAGE_DIRECTORY_COUNT);
    try std.testing.expectEqual(@as(usize, table64.TABLE_ENTRIES), IDENTITY_DIRECTORY_ENTRIES);
}

test "leaf mappings encode global and execute permissions explicitly" {
    const kernel_leaf = leafFlags(PAGE_PRESENT | PAGE_WRITABLE, true);
    try std.testing.expect((kernel_leaf & table64.NO_EXECUTE) != 0);
    try std.testing.expect((kernel_leaf & ENTRY_GLOBAL) != 0);

    const user_leaf = leafFlags(PAGE_PRESENT | PAGE_USER | PAGE_EXECUTABLE, false);
    try std.testing.expect((user_leaf & table64.NO_EXECUTE) == 0);
    try std.testing.expect((user_leaf & ENTRY_GLOBAL) == 0);
}
