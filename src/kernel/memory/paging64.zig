const std = @import("std");
const builtin = @import("builtin");
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
const kernel_address = @import("../../arch/kernel_address.zig");
const cpu_identity = @import("../cpu_identity.zig");
const physical_mapper = @import("kernel_physical_mapper.zig");
const cache_policy = @import("../../arch/cache_policy.zig");
const efi_paging = @import("../../boot/efi_paging.zig");
const efi_handoff = @import("../../boot/efi_handoff.zig");
const sparse = @import("../../arch/sparse_physical_map.zig");

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
pub const DIRECT_MAP_USES_1G_PAGES = virtual_layout.DIRECT_MAP_USES_1G_PAGES;
pub const USES_RUNTIME_2M_PAGES = virtual_layout.USES_RUNTIME_2M_PAGES;
pub const PRECISE_IMAGE_LIMIT_MATCHES_LINKER = true;

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
    protection_key: u4 = 0,
};

pub const UserMapError = error{
    OutOfMemory,
    InvalidRange,
    AddressOverflow,
    KernelMappingCollision,
    AlreadyMapped,
    WritableExecutable,
};

const KernelMappingOwnerError = error{WrongCpu};
pub const KernelMapError = UserMapError || KernelMappingOwnerError;
pub const DeviceMapError = physical_mapper.Error;

pub const UserWriteError = error{
    InvalidRange,
    AddressOverflow,
    PageNotOwned,
};

pub const UserAddressSpaceDestroyError = error{
    AddressSpaceActive,
};

pub const BorrowedKernelUnmapError = error{
    InvalidRange,
    AddressOverflow,
    MappingNotBorrowed,
    WrongCpu,
};

pub const UserAddressSpaceCreateError = error{
    OutOfMemory,
    ProcessContextExhausted,
};

pub const MANAGED_PHYSICAL_BYTES: frame_allocator.PhysicalAddress = 512 * 1024 * 1024 * 1024;
const LARGE_2M_PAGE_SIZE: frame_allocator.PhysicalAddress = 1 << PAGE_DIRECTORY_SHIFT;
const LARGE_1G_PAGE_SIZE: frame_allocator.PhysicalAddress = 1 << PDPT_SHIFT;
const PAGE_DIRECTORY_COVERAGE_BYTES = LARGE_1G_PAGE_SIZE;
const IDENTITY_DIRECTORY_ENTRIES: usize = @intCast(LOW_IDENTITY_PHYSICAL_LIMIT / LARGE_2M_PAGE_SIZE);
pub const DIRECT_MAP_PDPT_ENTRIES: usize = @intCast(MANAGED_PHYSICAL_BYTES / PAGE_DIRECTORY_COVERAGE_BYTES);
pub const SPARSE_CACHE_AWARE_RAM_MAP = true;
// Keep synchronized with __kernel_precise_image_physical_end in the linker script.
pub const PRECISE_IMAGE_PAGE_TABLES: usize = 32;
pub const PRECISE_IMAGE_BYTES: u32 = PRECISE_IMAGE_PAGE_TABLES * 2 * 1024 * 1024;

const TABLE_OWNER_INHERITED: u3 = 0;
const TABLE_OWNER_KERNEL_DYNAMIC: u3 = 1;
const TABLE_OWNER_USER_PRIVATE: u3 = 2;
const PAGE_OWNER_BORROWED: u3 = 0;
const PAGE_OWNER_USER_PRIVATE: u3 = 1;
const PAGE_OWNER_RETIRED_BORROWED: u3 = 3;
const PAGE_OWNER_RETIRED_PRIVATE: u3 = 4;

extern var stack_bottom: u8;
extern const __kernel_text_start: u8;
extern const __kernel_text_end: u8;
extern const __kernel_relro_end: u8;
extern const __kernel_precise_image_physical_end: u8;

var bootstrap_root: ?*PageDirectory = null;
var boot_arena_retirement: firmware_memory_map.BootArenaRetirement = .{};

pub fn bootPagingArenaRetirement() *const firmware_memory_map.BootArenaRetirement {
    return &boot_arena_retirement;
}

const PhysicalFrameAllocator = frame_allocator.Fixed(MANAGED_PHYSICAL_BYTES, PAGE_SIZE);
var physical_frames: PhysicalFrameAllocator = undefined;
var frame_lock = spin.Lock.init();
var high_memory_zone_has_free_frames: bool = false;
var low_identity_frame_cursor = frame_allocator.AllocationCursor{};
var process_contexts = pcid_allocator.Allocator.init();
var process_context_lock = spin.Lock.init();
var process_context_identifiers_enabled: bool = false;
var remote_pcid_shootdown: ?*const fn (u16) void = null;
var remote_kernel_shootdown: ?*const fn () void = null;
const DeviceAliasTransition = struct {
    begin: *const fn () void,
    flush: *const fn () void,
    end: *const fn () void,
};
var device_alias_transition: ?DeviceAliasTransition = null;
// The loader handoff and kernel extents remain owned and immutable after
// paging initialization. Scratch remaps need frame ownership checks, not a
// fresh parse of the same tagged handoff for every register-page access.
var kernel_mapping_authority: ?firmware_memory_map.KernelMappingAuthority = null;

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
    image_end: u32,
};

fn kernelImageLeafFlags(page_address: u32, image: KernelImageExtents) u64 {
    if (page_address < image.text_start or page_address >= image.image_end) return 0;
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
    const text_start = std.math.cast(u32, kernel_address.imagePhysicalAddress(@intFromPtr(&__kernel_text_start)) orelse
        haltPagingFailure(.kernel_text_outside_upper_half_image_window)) orelse
        haltPagingFailure(.kernel_text_outside_low_physical_aperture);
    const text_end = std.math.cast(u32, kernel_address.imagePhysicalAddress(@intFromPtr(&__kernel_text_end)) orelse
        haltPagingFailure(.kernel_text_outside_upper_half_image_window)) orelse
        haltPagingFailure(.kernel_text_outside_low_physical_aperture);
    const immutable_end = std.math.cast(u32, kernel_address.imagePhysicalAddress(@intFromPtr(&__kernel_relro_end)) orelse
        haltPagingFailure(.kernel_immutable_data_outside_upper_half_image_window)) orelse
        haltPagingFailure(.kernel_immutable_image_outside_low_physical_aperture);
    const precise_image_physical_end = std.math.cast(u32, @intFromPtr(&__kernel_precise_image_physical_end)) orelse
        haltPagingFailure(.kernel_precise_image_physical_limit_outside_low_physical_aperture);
    if (text_start % PAGE_SIZE != 0 or
        text_end % PAGE_SIZE != 0 or
        immutable_end % PAGE_SIZE != 0 or
        text_start >= text_end or
        text_end >= immutable_end or
        immutable_end > PRECISE_IMAGE_BYTES or
        precise_image_physical_end != PRECISE_IMAGE_BYTES)
    {
        haltPagingFailure(.invalid_page_aligned_kernel_image_extents);
    }
    const image_end = std.math.cast(u32, memory.kernelPhysicalEndAddress()) orelse
        haltPagingFailure(.kernel_end_outside_physical_image_aperture);
    if (image_end < immutable_end or image_end > LOW_IDENTITY_PHYSICAL_LIMIT)
        haltPagingFailure(.invalid_physical_kernel_image_end);
    return .{
        .text_start = text_start,
        .text_end = text_end,
        .immutable_end = immutable_end,
        .image_end = image_end,
    };
}

inline fn tableFromEntry(entry: PageTableEntry) *PageTable {
    return tableAtPhysical(@intCast(entryAddress(entry)));
}

inline fn tableAtPhysical(physical_address: frame_allocator.PhysicalAddress) *PageTable {
    return @ptrFromInt(directMapAddress(physical_address) orelse
        haltPagingFailure(.page_table_frame_outside_direct_map_aperture));
}

inline fn bytesAtPhysical(physical_address: frame_allocator.PhysicalAddress) [*]u8 {
    return @ptrFromInt(directMapAddress(physical_address) orelse
        haltPagingFailure(.data_frame_outside_direct_map_aperture));
}

inline fn tablePhysicalAddress(table: *const PageTable) frame_allocator.PhysicalAddress {
    return virtual_layout.directMappedPhysicalAddress(@intFromPtr(table), MANAGED_PHYSICAL_BYTES) orelse
        haltPagingFailure(.page_table_pointer_outside_direct_map_aperture);
}

inline fn kernelPageDirectory() *PageDirectory {
    return bootstrap_root orelse haltPagingFailure(.missing_kernel_page_table_root);
}

fn zeroTable(table: *PageTable) void {
    @memset(table, 0);
}

inline fn publishZeroedTable(entry: *PageTableEntry, table: *PageTable, value: PageTableEntry) void {
    zeroTable(table);
    // Release publication keeps initialization before the present entry, even
    // when another CPU is already walking this address space.
    @atomicStore(PageTableEntry, entry, value, .release);
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

fn releaseRetiredProcessContext(identifier: pcid_allocator.Identifier) void {
    acquireProcessContextLock();
    defer releaseProcessContextLock();
    process_contexts.release(identifier) catch
        haltPagingFailure(.corrupt_process_context_identifier_accounting);
}

pub fn setRemotePcidShootdown(hook: *const fn (u16) void) void {
    remote_pcid_shootdown = hook;
}

/// The callback returns only after every participating CPU has retired global
/// kernel translations. It must not allocate, acquire paging locks, or reenter
/// a mapping operation; retirement can invoke it while holding the frame lock.
pub fn setRemoteKernelShootdown(hook: *const fn () void) void {
    remote_kernel_shootdown = hook;
}

/// Install the complete held cache rendezvous as one coherent contract. The
/// callbacks must neither allocate nor acquire paging locks or reenter paging.
pub fn setDeviceAliasTransition(begin: *const fn () void, flush: *const fn () void, end: *const fn () void) void {
    device_alias_transition = .{ .begin = begin, .flush = flush, .end = end };
}

/// Strict UC device leaves replace every overlapping WB direct alias before
/// publication. The complete range either commits or leaves the hierarchy intact.
pub inline fn mapKernelDeviceRange(virtual_start: usize, physical_start: u64, size_bytes: usize, writable: bool) DeviceMapError!void {
    try mapKernelPhysicalRange(virtual_start, physical_start, size_bytes, .device, writable);
}

/// Firmware table aliases remain RO/NX/WB and retain their WB direct aliases.
pub inline fn mapKernelFirmwareRange(virtual_start: usize, physical_start: u64, size_bytes: usize) DeviceMapError!void {
    try mapKernelPhysicalRange(virtual_start, physical_start, size_bytes, .firmware, false);
}

inline fn mapKernelPhysicalRange(virtual_start: usize, physical_start: u64, size_bytes: usize, kind: physical_mapper.Kind, writable: bool) DeviceMapError!void {
    if (cpu_identity.currentIndex() != 0) return error.WrongCpu;
    if (@import("../interrupts/context.zig").active()) return error.InterruptContext;
    if (comptime builtin.target.os.tag != .freestanding) return error.Unavailable;
    if (!kernelAddressSpaceActive()) return error.WrongAddressSpace;
    var backend = KernelPhysicalMapping{};
    try physical_mapper.map(&backend, virtual_start, physical_start, size_bytes, kind, writable);
}

const KernelPhysicalMapping = struct {
    restore_interrupts: bool = false,

    pub inline fn root(_: *@This()) *PageDirectory {
        return kernelPageDirectory();
    }

    pub inline fn table(_: *@This(), entry: u64) ?*PageTable {
        const physical = entryAddress(entry);
        if (physical == 0 or physical >= MANAGED_PHYSICAL_BYTES) return null;
        return tableAtPhysical(physical);
    }

    pub inline fn tableAt(_: *@This(), physical: usize) *PageTable {
        return tableAtPhysical(physical);
    }

    pub inline fn validatePhysical(_: *@This(), start: u64, bytes: usize, kind: physical_mapper.Kind) DeviceMapError!void {
        const physical_bits = cache_policy.admittedPhysicalAddressBits() orelse return error.PhysicalOwnershipConflict;
        if (start + bytes > (@as(u64, 1) << @as(u6, @intCast(physical_bits)))) return error.InvalidRange;
        if (kind == .firmware) cache_policy.requireAdmittedWriteBack(start, bytes) catch return error.PhysicalOwnershipConflict;
        const authority = if (kernel_mapping_authority) |*authority| authority else return error.PhysicalOwnershipConflict;
        acquireFrameLock();
        defer releaseFrameLock();
        if (!authority.permits(&physical_frames, start, start + bytes, kind == .device)) return error.PhysicalOwnershipConflict;
    }

    pub inline fn validateTransition(_: *@This(), cache_changed: bool) DeviceMapError!void {
        if (cache_changed and device_alias_transition == null and @import("../smp.zig").onlineCpuCount() != 1)
            return error.CacheTransitionUnavailable;
    }

    pub inline fn reserveTables(_: *@This(), count: u32) ?physical_mapper.Pool {
        const run = allocGeneralFrames(count) orelse return null;
        return .{ .base = run.base, .count = run.count };
    }

    pub inline fn begin(self: *@This(), cache_changed: bool) void {
        if (cache_changed) {
            if (device_alias_transition) |transition| {
                transition.begin();
                return;
            }
        }
        self.restore_interrupts = x86.interruptsEnabled();
        x86.cli();
    }

    pub inline fn flush(_: *@This(), cache_changed: bool, translated_changed: bool) void {
        if (cache_changed) {
            if (device_alias_transition) |transition| {
                transition.flush();
                return;
            }
            x86.invalidateAllTranslations();
            x86.writeBackInvalidateCaches();
        } else if (translated_changed) {
            x86.invalidateAllTranslations();
            if (remote_kernel_shootdown) |shootdown| shootdown();
        }
        // Fresh absent-to-present same-cache aliases have no translation to
        // revoke. Their publication needs local INVLPG, but no remote barrier.
    }

    pub inline fn invalidateLocal(_: *@This(), address: usize) void {
        invalidate_page(address);
    }

    pub inline fn end(self: *@This(), cache_changed: bool) void {
        if (cache_changed) {
            if (device_alias_transition) |transition| {
                transition.end();
                return;
            }
        }
        if (self.restore_interrupts) x86.sti();
    }
};

test "typed physical mapping rejects foreign CPUs and interrupt context before hardware or allocation" {
    const context = @import("../interrupts/context.zig");
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    for (1..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        try std.testing.expectError(error.WrongCpu, mapKernelDeviceRange(virtual_layout.device_memory.base, 0xF0000000, PAGE_SIZE, true));
        try std.testing.expectError(error.WrongCpu, mapKernelFirmwareRange(virtual_layout.device_memory.base, 0x100000, PAGE_SIZE));
    }
    cpu_identity.setIndexForTest(0);
    context.enter();
    defer context.leave();
    try std.testing.expectError(error.InterruptContext, mapKernelDeviceRange(virtual_layout.device_memory.base, 0xF0000000, PAGE_SIZE, true));
    try std.testing.expectError(error.InterruptContext, mapKernelFirmwareRange(virtual_layout.device_memory.base, 0x100000, PAGE_SIZE));
}

fn invalidateUserContext(space: *const UserAddressSpace) void {
    invalidateUserContextWith(UserContextInvalidation{}, space.pcid, process_context_identifiers_enabled, space.directory == getCurrentPageDirectory());
}

const UserContextInvalidation = struct {
    fn invalidatePcid(_: @This(), identifier: u16) void {
        x86.invalidatePcid(identifier);
    }

    fn reloadCurrentRoot(_: @This()) void {
        x86.writeCr3(x86.readCr3());
    }

    fn invalidateRemote(_: @This(), identifier: u16) void {
        if (remote_pcid_shootdown) |shootdown| shootdown(identifier);
    }
};

fn invalidateUserContextWith(backend: anytype, identifier: u16, identifiers_enabled: bool, active: bool) void {
    if (identifiers_enabled) {
        backend.invalidatePcid(identifier);
    } else if (active) {
        backend.reloadCurrentRoot();
    }
    // The remote CPU chooses its own PCIDE-aware invalidation. The initiating
    // CPU's mode must not suppress retirement on other participating CPUs.
    backend.invalidateRemote(identifier);
}

const PagingFailure = enum {
    kernel_text_outside_upper_half_image_window,
    kernel_text_outside_low_physical_aperture,
    kernel_immutable_data_outside_upper_half_image_window,
    kernel_immutable_image_outside_low_physical_aperture,
    kernel_precise_image_physical_limit_outside_low_physical_aperture,
    invalid_page_aligned_kernel_image_extents,
    kernel_end_outside_physical_image_aperture,
    invalid_physical_kernel_image_end,
    page_table_frame_outside_direct_map_aperture,
    data_frame_outside_direct_map_aperture,
    page_table_pointer_outside_direct_map_aperture,
    missing_kernel_page_table_root,
    corrupt_process_context_identifier_accounting,
    allocated_frame_outside_low_identity_aperture,
    out_of_physical_memory_while_mapping_page,
    attempted_to_map_an_unaligned_page,
    user_mapping_collided_with_inherited_kernel_memory,
    attempted_to_replace_an_owned_user_page,
    attempted_to_create_a_writable_executable_user_page,
    page_mapping_address_overflow,
    corrupt_pml4_allocation_accounting,
    corrupt_rejected_huge_page_allocation_accounting,
    corrupt_retired_user_range_accounting,
    corrupt_retired_user_hierarchy_accounting,
    invalid_native_memory_map,
    native_memory_map_capacity_exceeded,
    invalid_framebuffer_ownership_extent,
    invalid_ram_direct_map_authority,
    final_paging_arena_outside_direct_map_aperture,
    sparse_kernel_hierarchy_admission_failed,
    corrupt_high_memory_probe_accounting,
    high_memory_probe_outside_direct_map_aperture,
    high_memory_direct_map_leaf_missing,
    high_memory_direct_map_permissions_are_invalid,
    high_memory_direct_map_probe_failed,
    missing_multiboot_memory_map_handoff,
    invalid_multiboot_information_extent,
    missing_multiboot_memory_map,
    missing_admitted_cache_policy,
    invalid_native_boot_memory_ownership,
    insufficient_early_heap_for_physical_frame_state,
    invalid_multiboot_memory_map,
    invalid_live_multiboot_handoff_extent,
    invalid_kernel_or_efi_heap_reservation,
    physical_memory_reservation_table_overflow,
    no_usable_physical_frames_remain_after_kernel_reservation,
    current_cpu_has_no_verified_paging_root,
    kernel_paging_root_not_initialized,
    current_cpu_failed_kernel_cr3_admission,
    address_space_root_exceeds_machine_address_width,
    invalid_address_space_cr3_value,
    address_space_switch_failed_cr3_readback,
    pcid_switch_requires_current_cpu_admission,
};

// Share cold diagnostics as bytes and bounded offsets, without one pointer
// relocation and standalone literal for every fatal path.
const paging_failure_messages = blk: {
    const messages = [_][]const u8{
        "Kernel text lies outside the upper-half image window!\n",
        "Kernel text lies outside the low physical aperture!\n",
        "Kernel immutable data lies outside the upper-half image window!\n",
        "Kernel immutable image lies outside the low physical aperture!\n",
        "Kernel precise image physical limit lies outside the low physical aperture!\n",
        "Invalid page-aligned kernel image extents!\n",
        "Kernel end lies outside the physical image aperture!\n",
        "Invalid physical kernel image end!\n",
        "Page-table frame lies outside the direct-map aperture!\n",
        "Data frame lies outside the direct-map aperture!\n",
        "Page-table pointer lies outside the direct-map aperture!\n",
        "Missing kernel page-table root!\n",
        "Corrupt process-context identifier accounting!\n",
        "Allocated frame lies outside the low identity aperture!\n",
        "Out of physical memory while mapping page!\n",
        "Attempted to map an unaligned page!\n",
        "User mapping collided with inherited kernel memory!\n",
        "Attempted to replace an owned user page!\n",
        "Attempted to create a writable executable user page!\n",
        "Page mapping address overflow!\n",
        "Corrupt PML4 allocation accounting!\n",
        "Corrupt rejected huge-page allocation accounting!\n",
        "Corrupt retired user-range accounting!\n",
        "Corrupt retired user-hierarchy accounting!\n",
        "Invalid native memory map!\n",
        "Native memory map capacity exceeded!\n",
        "Invalid framebuffer ownership extent!\n",
        "Invalid RAM direct-map authority!\n",
        "Final paging arena lies outside the direct-map aperture!\n",
        "Sparse kernel hierarchy admission failed!\n",
        "Corrupt high-memory probe accounting!\n",
        "High-memory probe lies outside the direct-map aperture!\n",
        "High-memory direct-map leaf is missing!\n",
        "High-memory direct-map permissions are invalid!\n",
        "High-memory direct-map probe failed!\n",
        "Missing Multiboot memory-map handoff!\n",
        "Invalid Multiboot information extent!\n",
        "Missing Multiboot memory map!\n",
        "Missing admitted cache policy!\n",
        "Invalid native boot memory ownership!\n",
        "Insufficient early heap for physical-frame state!\n",
        "Invalid Multiboot memory map!\n",
        "Invalid live Multiboot handoff extent!\n",
        "Invalid kernel or EFI heap reservation!\n",
        "Physical-memory reservation table overflow!\n",
        "No usable physical frames remain after kernel reservation!\n",
        "Current CPU has no verified paging root!\n",
        "Kernel paging root is not initialized!\n",
        "Current CPU failed kernel CR3 admission!\n",
        "Address-space root exceeds the machine address width!\n",
        "Invalid address-space CR3 value!\n",
        "Address-space switch failed CR3 readback!\n",
        "PCID switch requires current CPU admission!\n",
    };
    if (messages.len != @typeInfo(PagingFailure).@"enum".field_names.len)
        @compileError("paging failure messages must cover every reason");
    var byte_count: usize = 0;
    for (messages) |message| byte_count += message.len;
    if (byte_count > std.math.maxInt(u16)) @compileError("paging diagnostics exceed their bounded offsets");
    var bytes: []const u8 = "";
    var offsets: [messages.len + 1]u16 = undefined;
    var cursor: usize = 0;
    for (messages, 0..) |message, index| {
        offsets[index] = @intCast(cursor);
        bytes = bytes ++ message;
        cursor += message.len;
    }
    offsets[messages.len] = @intCast(cursor);
    break :blk .{ .bytes = bytes, .offsets = offsets };
};

noinline fn haltPagingFailure(reason: PagingFailure) noreturn {
    @branchHint(.cold);
    early_console.print(pagingFailureMessage(reason));
    while (true) x86.hlt();
}

fn pagingFailureMessage(reason: PagingFailure) []const u8 {
    const index: usize = @backingInt(reason);
    return paging_failure_messages.bytes[paging_failure_messages.offsets[index]..paging_failure_messages.offsets[index + 1]];
}

test "paging diagnostic runtime selectors retain addressable bytes for every fatal reason" {
    var selected: u8 = 0;
    const selector: *volatile u8 = &selected;
    const blob = paging_failure_messages.bytes;
    for (0..@typeInfo(PagingFailure).@"enum".field_names.len) |index| {
        selector.* = @intCast(index);
        const reason: PagingFailure = @fromBackingInt(@intCast(selector.*));
        const message = pagingFailureMessage(reason);
        try std.testing.expect(message.len != 0);
        try std.testing.expect(@intFromPtr(message.ptr) >= @intFromPtr(blob.ptr));
        try std.testing.expect(@intFromPtr(message.ptr) + message.len <= @intFromPtr(blob.ptr) + blob.len);
        try std.testing.expectEqual(@as(u8, '\n'), message[message.len - 1]);
    }
    selector.* = @backingInt(PagingFailure.invalid_native_boot_memory_ownership);
    try std.testing.expectEqualStrings("Invalid native boot memory ownership!\n", pagingFailureMessage(@fromBackingInt(@intCast(selector.*))));
}

inline fn lowIdentityFrameAddress(address: frame_allocator.PhysicalAddress) u32 {
    if (address >= LOW_IDENTITY_PHYSICAL_LIMIT) {
        haltPagingFailure(.allocated_frame_outside_low_identity_aperture);
    }
    return @intCast(address);
}

pub fn directMapAddress(address: frame_allocator.PhysicalAddress) ?usize {
    return virtual_layout.directMappedAddress(address, MANAGED_PHYSICAL_BYTES);
}

// Geometry alone does not prove that a sparse alias exists. Firmware readers
// use this complete-span check before forming a pointer into the direct map.
pub fn mappedRamSpan(physical: u64, bytes: u64) ?usize {
    return mappedRamSpanForAccess(physical, bytes, false);
}

/// Admit a retained user root only while its allocated directory still has a
/// writable WB kernel alias and names the same physical frame as its CR3.
pub inline fn checkedUserAddressSpacePhysicalRoot(space: *const UserAddressSpace) ?u64 {
    if (comptime builtin.target.os.tag != .freestanding) return null;
    const Backend = struct {
        inline fn owns(_: *@This(), physical: u64) bool {
            return physical_frames.isAllocated(physical) and !cachedFrame(physical);
        }

        inline fn writableAlias(_: *@This(), physical: u64) ?usize {
            return mappedRamSpanForAccess(physical, PAGE_SIZE, true);
        }
    };
    var backend = Backend{};
    acquireFrameLock();
    defer releaseFrameLock();
    return checkedUserRootWith(&backend, @intFromPtr(space.directory), space.switch_cr3);
}

inline fn checkedUserRootWith(backend: anytype, directory: usize, switch_cr3: usize) ?u64 {
    const physical = virtual_layout.directMappedPhysicalAddress(directory, MANAGED_PHYSICAL_BYTES) orelse return null;
    if (physical == 0 or physical % PAGE_SIZE != 0 or
        (switch_cr3 & ~(x86.CR3_ADDRESS_MASK | x86.CR3_PCID_MASK | x86.CR3_NO_FLUSH)) != 0 or
        (switch_cr3 & x86.CR3_ADDRESS_MASK) != physical or !backend.owns(physical)) return null;
    const alias = backend.writableAlias(physical) orelse return null;
    if (alias != directory) return null;
    return physical;
}

test "retained user root admission requires allocated backing and an exact writable WB alias" {
    const physical: u64 = 0x2000;
    const alias = directMapAddress(physical).?;
    const Backend = struct {
        allocated: bool = true,
        cached: bool = false,
        alias: ?usize,
        reads: usize = 0,

        fn owns(self: *@This(), value: u64) bool {
            return value == physical and self.allocated and !self.cached;
        }

        fn writableAlias(self: *@This(), value: u64) ?usize {
            self.reads += 1;
            return if (value == physical) self.alias else null;
        }
    };
    var backend = Backend{ .alias = alias };
    try std.testing.expectEqual(physical, checkedUserRootWith(&backend, alias, physical).?);
    try std.testing.expectEqual(physical, checkedUserRootWith(&backend, alias, physical | 17 | x86.CR3_NO_FLUSH).?);
    for ([_]struct { directory: usize, cr3: usize }{
        .{ .directory = 0, .cr3 = physical },
        .{ .directory = directMapAddress(0).?, .cr3 = 0 },
        .{ .directory = alias + 1, .cr3 = physical },
        .{ .directory = alias, .cr3 = physical + PAGE_SIZE },
        .{ .directory = alias, .cr3 = physical | (@as(usize, 1) << 62) },
    }) |invalid| {
        const before = backend.reads;
        try std.testing.expectEqual(@as(?u64, null), checkedUserRootWith(&backend, invalid.directory, invalid.cr3));
        try std.testing.expectEqual(before, backend.reads);
    }
    backend.allocated = false;
    try std.testing.expectEqual(@as(?u64, null), checkedUserRootWith(&backend, alias, physical));
    backend.allocated = true;
    backend.cached = true;
    try std.testing.expectEqual(@as(?u64, null), checkedUserRootWith(&backend, alias, physical));
    backend.cached = false;
    backend.alias = null;
    try std.testing.expectEqual(@as(?u64, null), checkedUserRootWith(&backend, alias, physical));
    backend.alias = alias + PAGE_SIZE;
    try std.testing.expectEqual(@as(?u64, null), checkedUserRootWith(&backend, alias, physical));
}

fn mappedRamSpanForAccess(physical: u64, bytes: u64, write: bool) ?usize {
    if (comptime builtin.target.os.tag != .freestanding) return null;
    const cache = cache_policy.admittedMtrrView() catch return null;
    const info = handoff.capturedInfo() orelse return null;
    const memory_map = handoff.capturedMemoryMap(info) orelse return null;
    firmware_memory_map.requireRamWriteBack(memory_map, physical, bytes, cache) catch return null;
    var backend = DirectSpanTables{};
    const root = if (kernel_switch_cr3 != 0)
        trackedCurrentDirectory() catch return null
    else boot: {
        const arenas = info.boot_paging orelse return null;
        arenas.validate() catch return null;
        const root_physical = x86.readCr3() & x86.CR3_ADDRESS_MASK;
        if (root_physical != arenas.transition_base) return null;
        backend.transition = .{ .start = arenas.transition_base, .end = arenas.transition_base + arenas.transitionBytes() };
        firmware_memory_map.requireRamWriteBack(memory_map, arenas.transition_base, arenas.transitionBytes(), cache) catch return null;
        break :boot backend.table(root_physical | ENTRY_PRESENT) orelse return null;
    };
    return mappedRamSpanPermissionsWith(&backend, root, physical, bytes, cache, write);
}

const DirectSpanTables = struct {
    transition: ?firmware_memory_map.PhysicalSpan = null,

    fn table(self: *@This(), entry: u64) ?*const PageTable {
        const physical = entryAddress(entry);
        if (physical == 0 or physical >= MANAGED_PHYSICAL_BYTES or physical % PAGE_SIZE != 0) return null;
        if (self.transition) |arena| {
            if (physical < arena.start or physical > arena.end - PAGE_SIZE) return null;
        }
        cache_policy.requireAdmittedWriteBack(physical, PAGE_SIZE) catch return null;
        return @ptrFromInt(directMapAddress(physical) orelse return null);
    }
};

fn mappedRamSpanWith(backend: anytype, root: *const PageTable, physical: u64, bytes: u64, cache: cache_policy.ValidatedMtrrView) ?usize {
    return mappedRamSpanPermissionsWith(backend, root, physical, bytes, cache, false);
}

fn mappedRamSpanPermissionsWith(backend: anytype, root: *const PageTable, physical: u64, bytes: u64, cache: cache_policy.ValidatedMtrrView, write: bool) ?usize {
    const end = std.math.add(u64, physical, bytes) catch return null;
    if (bytes == 0 or end > MANAGED_PHYSICAL_BYTES) return null;
    cache.requireWriteBack(physical, bytes) catch return null;
    const alias = directMapAddress(physical) orelse return null;
    var cursor = physical;
    while (cursor < end) {
        const virtual = directMapAddress(cursor) orelse return null;
        var current = root;
        var found = false;
        for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT, PAGE_TABLE_SHIFT }, 0..) |shift, level| {
            const entry = current[tableIndex(virtual, shift)];
            if (!entryPresent(entry) or entry & ENTRY_USER != 0 or (write and entry & ENTRY_WRITABLE == 0)) return null;
            const large = level != 3 and table64.isLargePage(entry);
            if (large and level != 1 and level != 2) return null;
            if (large or level == 3) {
                const leaf_bytes: u64 = if (large) @as(u64, 1) << shift else PAGE_SIZE;
                const pat_bit: u64 = if (large) 1 << 12 else ENTRY_LARGE_PAGE;
                if (table64.isExecutable(entry) or entry & (ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE | pat_bit) != 0 or
                    entryAddress(entry) != (cursor & ~(leaf_bytes - 1))) return null;
                cursor = @min(end, (cursor & ~(leaf_bytes - 1)) + leaf_bytes);
                found = true;
                break;
            }
            if (entry & (ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE) != 0) return null;
            current = backend.table(entry) orelse return null;
        }
        if (!found) return null;
    }
    return alias;
}

test "sparse physical readers prove complete supervisor NX WB aliases before pointers" {
    const Model = struct {
        pdpt: PageTable = @splat(0),
        directory: PageTable = @splat(0),
        pages: PageTable = @splat(0),
        reads: usize = 0,

        fn table(self: *@This(), entry: u64) ?*const PageTable {
            self.reads += 1;
            return switch (entryAddress(entry)) {
                0x1000 => &self.pdpt,
                0x2000 => &self.directory,
                0x3000 => &self.pages,
                else => null,
            };
        }
    };
    const state: cache_policy.MtrrState = .{ .physical_bits = 36, .default_type = cache_policy.MTRR_ENABLED | 6 };
    const view = try cache_policy.ValidatedMtrrView.init(&state);
    var root: PageTable = @splat(0);
    root[256] = 0x1000 | ENTRY_PRESENT;
    var model = Model{};
    model.pdpt[0] = 0x2000 | ENTRY_PRESENT;
    model.directory[0] = 0x3000 | ENTRY_PRESENT;
    const valid = 0x5000 | ENTRY_PRESENT | table64.NO_EXECUTE;
    model.pages[5] = valid;
    try std.testing.expectEqual(directMapAddress(0x5000), mappedRamSpanWith(&model, &root, 0x5000, PAGE_SIZE, view));
    try std.testing.expect(mappedRamSpanPermissionsWith(&model, &root, 0x5000, PAGE_SIZE, view, true) == null);
    root[256] |= ENTRY_WRITABLE;
    model.pdpt[0] |= ENTRY_WRITABLE;
    model.directory[0] |= ENTRY_WRITABLE;
    model.pages[5] |= ENTRY_WRITABLE;
    try std.testing.expectEqual(directMapAddress(0x5000), mappedRamSpanPermissionsWith(&model, &root, 0x5000, PAGE_SIZE, view, true));
    for ([_]*u64{ &root[256], &model.pdpt[0], &model.directory[0], &model.pages[5] }) |entry| {
        entry.* &= ~ENTRY_WRITABLE;
        try std.testing.expect(mappedRamSpanPermissionsWith(&model, &root, 0x5000, PAGE_SIZE, view, true) == null);
        try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, PAGE_SIZE, view) != null);
        entry.* |= ENTRY_WRITABLE;
    }
    model.pages[5] = valid;
    try std.testing.expectEqual(directMapAddress(0x5fff), mappedRamSpanWith(&model, &root, 0x5fff, 1, view));
    try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5fff, 2, view) == null);
    for ([_]u64{ valid | ENTRY_USER, valid | ENTRY_WRITE_THROUGH, valid | ENTRY_CACHE_DISABLE, valid | ENTRY_LARGE_PAGE, valid & ~table64.NO_EXECUTE, valid & ~ENTRY_PRESENT, valid + PAGE_SIZE }) |invalid| {
        model.pages[5] = invalid;
        try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, 1, view) == null);
    }
    model.pages[5] = valid;
    root[256] |= ENTRY_USER;
    model.reads = 0;
    try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, 1, view) == null);
    try std.testing.expectEqual(@as(usize, 0), model.reads);
    root[256] &= ~ENTRY_USER;
    for ([_]u64{ ENTRY_WRITE_THROUGH, ENTRY_CACHE_DISABLE }) |selector| {
        root[256] |= selector;
        model.reads = 0;
        try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, 1, view) == null);
        try std.testing.expectEqual(@as(usize, 0), model.reads);
        root[256] &= ~selector;
    }
    model.directory[0] = ENTRY_PRESENT | ENTRY_LARGE_PAGE | table64.NO_EXECUTE;
    try std.testing.expectEqual(directMapAddress(0x5000), mappedRamSpanWith(&model, &root, 0x5000, PAGE_SIZE, view));
    model.pdpt[0] = ENTRY_PRESENT | ENTRY_LARGE_PAGE | table64.NO_EXECUTE;
    try std.testing.expectEqual(directMapAddress(0x5000), mappedRamSpanWith(&model, &root, 0x5000, LARGE_2M_PAGE_SIZE, view));
    // A requested WB/UC crossing is rejected before any hierarchy read.
    var mixed_state = state;
    mixed_state.capabilities = 1;
    mixed_state.variable[0] = .{ .base = 0x6000, .mask = (((@as(u64, 1) << 36) - 1) & ~@as(u64, PAGE_SIZE - 1)) | cache_policy.MTRR_VALID };
    const mixed = try cache_policy.ValidatedMtrrView.init(&mixed_state);
    model.reads = 0;
    try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5fff, 2, mixed) == null);
    try std.testing.expectEqual(@as(usize, 0), model.reads);
    for ([_]u64{ 0, std.math.maxInt(u64) }) |length| {
        try std.testing.expect(mappedRamSpanWith(&model, &root, 0x5000, length, mixed) == null);
    }
}

pub const SIPI_PHYSICAL_LIMIT: frame_allocator.PhysicalAddress = 1024 * 1024;
var reserved_sipi_page: ?u32 = null;

fn selectSipiPage(allocator: anytype) ?u32 {
    // Select from firmware-validated free pages before reserving the low
    // aperture. The blanket reservation then keeps the bridge owned forever.
    var physical: u32 = PAGE_SIZE;
    while (physical < SIPI_PHYSICAL_LIMIT) : (physical += PAGE_SIZE) {
        if (!allocator.isReserved(physical)) return physical;
    }
    return null;
}

pub fn claimSipiTrampolinePage() ?u32 {
    acquireFrameLock();
    defer releaseFrameLock();
    const page = reserved_sipi_page;
    reserved_sipi_page = null;
    return page;
}

pub const USES_PER_CPU_FRAME_CACHE = true;
const FRAME_CACHE_CPUS = @import("../cpu_identity.zig").MAX_CPUS;
const FRAME_CACHE_DEPTH: u8 = 16;
const FrameCacheTotal = u16;
comptime {
    if (FRAME_CACHE_CPUS * FRAME_CACHE_DEPTH > std.math.maxInt(FrameCacheTotal))
        @compileError("aggregate frame-cache ownership must fit its counter");
}
var general_frame_cache: [FRAME_CACHE_CPUS][FRAME_CACHE_DEPTH]frame_allocator.PhysicalAddress = undefined;
var general_frame_cache_len: [FRAME_CACHE_CPUS]u8 = @as([FRAME_CACHE_CPUS]u8, @splat(0));
var general_frame_cache_total: FrameCacheTotal = 0;

fn frameCacheCpu() u8 {
    if (comptime builtin.target.os.tag != .freestanding) return 0;
    return @import("../cpu_identity.zig").currentIndex();
}

fn cachedFrame(base: frame_allocator.PhysicalAddress) bool {
    return cachedFrameSpan(base, 1);
}

inline fn cachedFrameSpan(base: frame_allocator.PhysicalAddress, bytes: u64) bool {
    if (general_frame_cache_total == 0) return false;
    for (&general_frame_cache, 0..) |*cache, cpu_index| {
        var index: u8 = 0;
        while (index < general_frame_cache_len[cpu_index]) : (index += 1) {
            if (cache[index] >= base and cache[index] - base < bytes) return true;
        }
    }
    return false;
}

fn takeCachedFrameLocked() ?frame_allocator.PhysicalAddress {
    return takeCpuCachedFrameLocked(frameCacheCpu());
}

fn takeCpuCachedFrameLocked(cpu: usize) ?frame_allocator.PhysicalAddress {
    if (general_frame_cache_len[cpu] == 0) return null;
    general_frame_cache_len[cpu] -= 1;
    general_frame_cache_total -= 1;
    return general_frame_cache[cpu][general_frame_cache_len[cpu]];
}

// Preserve each CPU's local reuse until the backing allocator is exhausted.
// The shared frame lock makes a pressure transfer a single ownership change.
fn takeRemoteCachedFrameLocked() ?frame_allocator.PhysicalAddress {
    if (general_frame_cache_total == 0) return null;
    const local_cpu = frameCacheCpu();
    for (0..FRAME_CACHE_CPUS) |cpu| {
        if (cpu == local_cpu) continue;
        if (takeCpuCachedFrameLocked(cpu)) |base| return base;
    }
    return null;
}

fn stashCachedFrameLocked(base: frame_allocator.PhysicalAddress) bool {
    return stashCpuCachedFrameLocked(frameCacheCpu(), base);
}

inline fn stashCpuCachedFrameLocked(cpu: usize, base: frame_allocator.PhysicalAddress) bool {
    if (general_frame_cache_len[cpu] >= FRAME_CACHE_DEPTH) return false;
    general_frame_cache[cpu][general_frame_cache_len[cpu]] = base;
    general_frame_cache_len[cpu] += 1;
    general_frame_cache_total += 1;
    return true;
}

fn flushFrameCachesLocked() void {
    flushFrameCachesTo(&physical_frames, &high_memory_zone_has_free_frames, LOW_IDENTITY_PHYSICAL_LIMIT);
}

// Isolated fixtures drain retained free frames before an exact raw-allocation
// baseline. Production statistics and cache ownership semantics stay intact.
pub fn drainFrameCachesForArchitectureProof() void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    if (comptime !@hasDecl(@import("root"), "ARCHITECTURE_SMP_PROOF")) @compileError("frame-cache drain requires the isolated architecture image");
    if (comptime !@import("root").ARCHITECTURE_SMP_PROOF) @compileError("frame-cache drain requires the isolated architecture image");
    requireKernelMappingOwner() catch @panic("frame-cache proof drain requires the BSP runtime owner");
    if (x86.interruptsEnabled()) @panic("frame-cache proof drain requires disabled interrupts");
    acquireFrameLock();
    defer releaseFrameLock();
    flushFrameCachesLocked();
}

fn flushFrameCachesTo(allocator: anytype, high_zone_has_free_frames: *bool, low_identity_limit: frame_allocator.PhysicalAddress) void {
    for (&general_frame_cache, 0..) |*cache, cpu_index| {
        var index: u8 = 0;
        while (index < general_frame_cache_len[cpu_index]) : (index += 1) {
            const base = cache[index];
            allocator.releaseFrame(base) catch @panic("corrupt cached frame ownership");
            if (base >= low_identity_limit) high_zone_has_free_frames.* = true;
        }
        general_frame_cache_len[cpu_index] = 0;
    }
    general_frame_cache_total = 0;
}

pub fn allocGeneralFrame() ?frame_allocator.PhysicalAddress {
    acquireFrameLock();
    defer releaseFrameLock();
    return allocGeneralFrameFrom(
        &physical_frames,
        &high_memory_zone_has_free_frames,
        &low_identity_frame_cursor,
        LOW_IDENTITY_PHYSICAL_LIMIT,
        MANAGED_PHYSICAL_BYTES,
    );
}

fn allocGeneralFrameFrom(
    allocator: anytype,
    high_zone_has_free_frames: *bool,
    low_cursor: *frame_allocator.AllocationCursor,
    low_identity_limit: frame_allocator.PhysicalAddress,
    managed_bytes: frame_allocator.PhysicalAddress,
) ?frame_allocator.PhysicalAddress {
    if (takeCachedFrameLocked()) |base| return base;
    if (high_zone_has_free_frames.*) {
        if (allocator.allocateFrameBetween(low_identity_limit, managed_bytes)) |base| {
            return base;
        }
        high_zone_has_free_frames.* = false;
    }
    if (allocator.allocateBelowWithCursor(1, low_identity_limit, low_cursor)) |run| return run.base;
    return takeRemoteCachedFrameLocked();
}

pub fn allocGeneralFrames(count: u32) ?FrameRun {
    acquireFrameLock();
    defer releaseFrameLock();
    return allocGeneralFramesLocked(count);
}

// Explicit physical bounds apply to the complete run. Cached frames remain
// owned until a failed search drains them under the same allocator lock.
pub fn allocGeneralFramesBetween(count: u32, start: frame_allocator.PhysicalAddress, end: frame_allocator.PhysicalAddress) ?FrameRun {
    if (count == 0 or start % PAGE_SIZE != 0 or end % PAGE_SIZE != 0 or
        start >= end or end > MANAGED_PHYSICAL_BYTES or
        @as(u64, count) * PAGE_SIZE > end - start) return null;
    acquireFrameLock();
    defer releaseFrameLock();
    if (physical_frames.allocateBetween(count, start, end)) |run| return run;
    flushFrameCachesLocked();
    return physical_frames.allocateBetween(count, start, end);
}

fn allocGeneralFramesLocked(count: u32) ?FrameRun {
    if (allocGeneralRunFrom(
        &physical_frames,
        &high_memory_zone_has_free_frames,
        &low_identity_frame_cursor,
        count,
        LOW_IDENTITY_PHYSICAL_LIMIT,
        MANAGED_PHYSICAL_BYTES,
    )) |run| return run;
    flushFrameCachesLocked();
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

fn allocGeneralAlignedFrames(count: u32, alignment_frames: u32) ?FrameRun {
    acquireFrameLock();
    defer releaseFrameLock();
    if (allocGeneralAlignedRunFrom(
        &physical_frames,
        high_memory_zone_has_free_frames,
        &low_identity_frame_cursor,
        count,
        alignment_frames,
        LOW_IDENTITY_PHYSICAL_LIMIT,
        MANAGED_PHYSICAL_BYTES,
    )) |run| return run;
    flushFrameCachesLocked();
    return allocGeneralAlignedRunFrom(
        &physical_frames,
        high_memory_zone_has_free_frames,
        &low_identity_frame_cursor,
        count,
        alignment_frames,
        LOW_IDENTITY_PHYSICAL_LIMIT,
        MANAGED_PHYSICAL_BYTES,
    );
}

fn allocGeneralAlignedRunFrom(
    allocator: anytype,
    high_zone_has_free_frames: bool,
    low_cursor: *frame_allocator.AllocationCursor,
    count: u32,
    alignment_frames: u32,
    low_identity_limit: frame_allocator.PhysicalAddress,
    managed_bytes: frame_allocator.PhysicalAddress,
) ?FrameRun {
    if (high_zone_has_free_frames) {
        if (allocator.allocateAlignedBetween(count, alignment_frames, low_identity_limit, managed_bytes)) |run| return run;
    }
    return allocator.allocateAlignedBetweenWithCursor(count, alignment_frames, 0, low_identity_limit, low_cursor);
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

pub inline fn releaseGeneralFrames(run: FrameRun) FrameReleaseError!void {
    return releasePhysicalFrames(run.base, run.count);
}

pub fn releaseGeneralFrame(base: frame_allocator.PhysicalAddress) FrameReleaseError!void {
    acquireFrameLock();
    defer releaseFrameLock();
    if (cachedFrame(base)) return error.NotAllocated;
    if (!physical_frames.isAllocated(base)) return physical_frames.releaseFrame(base);
    if (stashCachedFrameLocked(base)) return;
    try physical_frames.releaseFrame(base);
    if (base >= LOW_IDENTITY_PHYSICAL_LIMIT) high_memory_zone_has_free_frames = true;
}

inline fn releasePhysicalFrames(base: frame_allocator.PhysicalAddress, count: u32) FrameReleaseError!void {
    acquireFrameLock();
    defer releaseFrameLock();
    try releasePhysicalFramesLocked(base, count);
}

fn releasePhysicalFramesLocked(base: frame_allocator.PhysicalAddress, count: u32) FrameReleaseError!void {
    try releaseRunTo(&physical_frames, &high_memory_zone_has_free_frames, .{
        .base = base,
        .count = count,
    }, LOW_IDENTITY_PHYSICAL_LIMIT);
}

fn releaseRunTo(
    allocator: anytype,
    high_zone_has_free_frames: *bool,
    run: FrameRun,
    low_identity_limit: frame_allocator.PhysicalAddress,
) FrameReleaseError!void {
    const capacity = @as(u64, @TypeOf(allocator.*).total_frames) * PAGE_SIZE;
    // Invalid geometry retains the allocator's original error precedence.
    // A valid caller-owned run cannot contain a frame already released into
    // any CPU cache, even though those bitmap bits remain allocated.
    if (run.count != 0 and run.base % PAGE_SIZE == 0 and run.base < capacity and
        run.count <= (capacity - run.base) / PAGE_SIZE and
        cachedFrameSpan(run.base, @as(u64, run.count) * PAGE_SIZE)) return error.NotAllocated;
    try allocator.release(run);
    // The validated run may start below the boundary and still return high frames.
    const end = run.base + @as(frame_allocator.PhysicalAddress, run.count) * PAGE_SIZE;
    if (end > low_identity_limit) high_zone_has_free_frames.* = true;
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
        const table = tableAtPhysical(table_phys);
        publishZeroedTable(entry, table, tableEntry(@intCast(table_phys), flags, owner));
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

pub fn mapBorrowedPhysicalUserRange(
    space: *UserAddressSpace,
    virtual_start: usize,
    physical_start: u64,
    size_bytes: usize,
    permissions: UserPermissions,
) UserMapError!void {
    if (permissions.write_through or permissions.cache_disabled) return error.InvalidRange;
    if (pageOffset(virtual_start) != 0 or size_bytes == 0) return error.InvalidRange;
    if (physical_start > std.math.maxInt(usize)) return error.InvalidRange;
    const physical_address: usize = @intCast(physical_start);
    if (pageOffset(physical_address) != 0) return error.InvalidRange;
    if (permissions.writable and permissions.executable) return error.WritableExecutable;
    if (permissions.executable) return error.WritableExecutable;

    const mapped_size = try checkedUserMappedSize(virtual_start, size_bytes);
    const physical_last_page = std.math.add(usize, physical_address, mapped_size - PAGE_SIZE) catch
        return error.AddressOverflow;
    if (!table64.physicalAddressFits(physical_last_page)) return error.InvalidRange;

    var offset: usize = 0;
    while (offset < mapped_size) : (offset += PAGE_SIZE) {
        try validateOwnedMappingSlot(space, virtual_start + offset);
    }

    offset = 0;
    while (offset < mapped_size) : (offset += PAGE_SIZE) {
        var flags: u32 = PAGE_PRESENT | PAGE_USER;
        if (permissions.writable) flags |= PAGE_WRITABLE;
        if (permissions.write_through) flags |= PAGE_WRITE_THROUGH;
        if (permissions.cache_disabled) flags |= PAGE_CACHE_DISABLE;
        try mapBorrowedPageIn(
            space.directory,
            virtual_start + offset,
            physical_address + offset,
            flags,
            TABLE_OWNER_USER_PRIVATE,
            false,
        );
    }
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

    publishLeafMutation(
        LeafInvalidation{ .local = global or (page_entry.* & ENTRY_GLOBAL) != 0 or pml4 == getCurrentPageDirectory() },
        page_entry,
        tableEntry(phys_addr, leafFlags(flags, global), PAGE_OWNER_BORROWED),
        virt_addr,
    );
}

const LeafInvalidation = struct {
    local: bool = true,

    fn invalidateLocal(self: @This(), address: usize) void {
        if (self.local) invalidate_page(address);
    }

    fn invalidateRemoteKernel(_: @This()) void {
        if (remote_kernel_shootdown) |shootdown| shootdown();
    }
};

fn publishLeafMutation(backend: anytype, entry: *PageTableEntry, replacement: PageTableEntry, address: usize) void {
    const old = @atomicLoad(PageTableEntry, entry, .monotonic);
    // Hardware access/dirty updates do not change the requested mapping. Keep
    // those bits intact instead of needlessly invalidating an identical leaf.
    const hardware_bits: u64 = PAGE_ACCESSED | PAGE_DIRTY;
    if ((old & ~hardware_bits) == (replacement & ~hardware_bits)) return;
    @atomicStore(PageTableEntry, entry, replacement, .release);
    backend.invalidateLocal(address);
    // A fresh absent-to-present leaf has no cached translation to revoke.
    // Existing global translations survive context switches and must be
    // retired on every CPU before an old backing frame can be reused.
    if (entryPresent(old) and ((old | replacement) & ENTRY_GLOBAL) != 0)
        backend.invalidateRemoteKernel();
}

fn requireKernelMappingOwner() KernelMappingOwnerError!void {
    // Kernel mappings belong to the sole runtime owner, including before SMP
    // admission. Check before mutation even when no remote flush is needed.
    if (cpu_identity.currentIndex() != 0) return error.WrongCpu;
}

fn publishCurrentLeafMutation(backend: anytype, entry: *PageTableEntry, replacement: PageTableEntry, address: usize) KernelMappingOwnerError!void {
    if (((entry.* | replacement) & ENTRY_GLOBAL) != 0) try requireKernelMappingOwner();
    publishLeafMutation(backend, entry, replacement, address);
}

test "kernel mapping ownership rejects every nonowner before allocation publication or invalidation" {
    const Model = struct {
        invalidations: usize = 0,

        fn invalidateLocal(self: *@This(), _: usize) void {
            self.invalidations += 1;
        }

        fn invalidateRemoteKernel(self: *@This()) void {
            self.invalidations += 1;
        }
    };
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    const global = tableEntry(0xA000, ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_GLOBAL | table64.NO_EXECUTE, PAGE_OWNER_BORROWED);
    var model = Model{};
    for (1..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        // Neither public call may touch uninitialized kernel tables or the
        // frame allocator: ownership is checked before their first access.
        try std.testing.expectError(error.WrongCpu, tryMapKernelBorrowedPage(virtual_layout.native_stacks.base, 0xA000, PAGE_PRESENT | PAGE_WRITABLE));
        try std.testing.expectError(error.WrongCpu, unmapBorrowedKernelRange(virtual_layout.native_stacks.base, PAGE_SIZE));
        var entry = global;
        try std.testing.expectError(error.WrongCpu, publishCurrentLeafMutation(&model, &entry, global & ~ENTRY_WRITABLE, 0x4000));
        try std.testing.expectError(error.WrongCpu, publishCurrentLeafMutation(&model, &entry, 0, 0x4000));
        try std.testing.expectEqual(global, entry);
        entry = 0;
        try std.testing.expectError(error.WrongCpu, publishCurrentLeafMutation(&model, &entry, global, 0x4000));
        try std.testing.expectEqual(@as(PageTableEntry, 0), entry);
        try std.testing.expectEqual(@as(usize, 0), model.invalidations);
    }
    // Private user leaves retain their separate address-space ownership rules.
    var nonglobal = global & ~ENTRY_GLOBAL;
    try publishCurrentLeafMutation(&model, &nonglobal, nonglobal & ~ENTRY_WRITABLE, 0x4000);
    try std.testing.expect((nonglobal & ENTRY_WRITABLE) == 0);
    try std.testing.expectEqual(@as(usize, 1), model.invalidations);
    cpu_identity.setIndexForTest(0);
    try requireKernelMappingOwner();
    var entry = global;
    try publishCurrentLeafMutation(&model, &entry, 0, 0x4000);
    try std.testing.expectEqual(@as(PageTableEntry, 0), entry);
    try std.testing.expectEqual(@as(usize, 3), model.invalidations);
}

test "global leaf mutations publish before barriers and skip fresh or identical remote invalidations" {
    const Model = struct {
        entry: PageTableEntry = 0,
        expected: PageTableEntry = 0,
        local_count: usize = 0,
        remote_count: usize = 0,
        local_seen: bool = false,
        valid: bool = true,

        fn invalidateLocal(self: *@This(), address: usize) void {
            if (address != 0x4000 or @atomicLoad(PageTableEntry, &self.entry, .acquire) != self.expected)
                self.valid = false;
            self.local_count += 1;
            self.local_seen = true;
        }

        fn invalidateRemoteKernel(self: *@This()) void {
            if (!self.local_seen or @atomicLoad(PageTableEntry, &self.entry, .acquire) != self.expected)
                self.valid = false;
            self.remote_count += 1;
            self.local_seen = false;
        }
    };
    var model = Model{};
    const flags = ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_GLOBAL | table64.NO_EXECUTE;
    model.expected = tableEntry(0xA000, flags, PAGE_OWNER_BORROWED);
    publishLeafMutation(&model, &model.entry, model.expected, 0x4000);
    try std.testing.expectEqual(@as(usize, 1), model.local_count);
    try std.testing.expectEqual(@as(usize, 0), model.remote_count);
    model.entry |= PAGE_ACCESSED | PAGE_DIRTY;
    const accessed = model.entry;
    publishLeafMutation(&model, &model.entry, model.expected, 0x4000);
    try std.testing.expectEqual(accessed, model.entry);
    try std.testing.expectEqual(@as(usize, 1), model.local_count);
    model.expected = tableEntry(0xB000, flags, PAGE_OWNER_BORROWED);
    publishLeafMutation(&model, &model.entry, model.expected, 0x4000);
    model.expected &= ~ENTRY_WRITABLE;
    publishLeafMutation(&model, &model.entry, model.expected, 0x4000);
    publishLeafMutation(&model, &model.entry, model.expected, 0x4000);
    try std.testing.expectEqual(@as(usize, 3), model.local_count);
    try std.testing.expectEqual(@as(usize, 2), model.remote_count);
    // Removing GLOBAL still has to retire the old globally cached translation.
    model.expected &= ~ENTRY_GLOBAL;
    publishLeafMutation(&model, &model.entry, model.expected, 0x4000);
    try std.testing.expectEqual(@as(usize, 3), model.remote_count);
    model.expected = 0;
    publishLeafMutation(&model, &model.entry, model.expected, 0x4000);
    try std.testing.expectEqual(@as(usize, 3), model.remote_count);
    // A present non-global leaf gaining GLOBAL also requires the barrier.
    model.entry = tableEntry(0xC000, flags & ~ENTRY_GLOBAL, PAGE_OWNER_BORROWED);
    model.expected = model.entry | ENTRY_GLOBAL;
    publishLeafMutation(&model, &model.entry, model.expected, 0x4000);
    model.expected = 0;
    publishLeafMutation(&model, &model.entry, 0, 0x4000);
    try std.testing.expectEqual(@as(usize, 5), model.remote_count);
    try std.testing.expect(model.valid);
}

fn mapFailure(error_value: KernelMapError) noreturn {
    switch (error_value) {
        error.OutOfMemory => haltPagingFailure(.out_of_physical_memory_while_mapping_page),
        error.InvalidRange => haltPagingFailure(.attempted_to_map_an_unaligned_page),
        error.KernelMappingCollision => haltPagingFailure(.user_mapping_collided_with_inherited_kernel_memory),
        error.AlreadyMapped => haltPagingFailure(.attempted_to_replace_an_owned_user_page),
        error.WritableExecutable => haltPagingFailure(.attempted_to_create_a_writable_executable_user_page),
        error.AddressOverflow => haltPagingFailure(.page_mapping_address_overflow),
        error.WrongCpu => @panic("kernel mapping requires the BSP runtime owner"),
    }
}

pub fn mapKernelBorrowedPage(virt_addr: usize, phys_addr: usize, flags: u32) void {
    tryMapKernelBorrowedPage(virt_addr, phys_addr, flags) catch |err| mapFailure(err);
}

pub fn tryMapKernelBorrowedPage(virt_addr: usize, phys_addr: usize, flags: u32) KernelMapError!void {
    try requireKernelMappingOwner();
    if (!table64.isCanonicalVirtualAddress(virt_addr) or !table64.physicalAddressFits(phys_addr))
        return error.InvalidRange;
    if ((flags & (PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH)) != 0) return error.InvalidRange;
    if (comptime builtin.target.os.tag == .freestanding) {
        const direct = directMapAddress(phys_addr) orelse return error.InvalidRange;
        const leaf = lookupLeaf(kernelPageDirectory(), direct) orelse return error.InvalidRange;
        const pat_bit: u64 = if (table64.isLargePage(leaf.*)) 1 << 12 else ENTRY_LARGE_PAGE;
        if (!entryPresent(leaf.*) or (leaf.* & (ENTRY_CACHE_DISABLE | ENTRY_WRITE_THROUGH | pat_bit)) != 0)
            return error.InvalidRange;
    }
    try mapBorrowedPageIn(kernelPageDirectory(), virt_addr, phys_addr, flags & ~PAGE_USER, TABLE_OWNER_KERNEL_DYNAMIC, true);
}

pub inline fn kernelAddressSpaceActive() bool {
    return getCurrentPageDirectory() == kernelPageDirectory();
}

fn lookupLeaf(pml4: *PageDirectory, virt_addr: usize) ?*PageTableEntry {
    const pml4_entry = pml4[tableIndex(virt_addr, PML4_SHIFT)];
    if (!entryPresent(pml4_entry)) return null;
    const pdpt = tableFromEntry(pml4_entry);
    const pdpt_entry = &pdpt[tableIndex(virt_addr, PDPT_SHIFT)];
    if ((pdpt_entry.* & ENTRY_LARGE_PAGE) != 0) return pdpt_entry;
    if (!entryPresent(pdpt_entry.*)) return null;
    const page_directory = tableFromEntry(pdpt_entry.*);
    const directory_entry = &page_directory[tableIndex(virt_addr, PAGE_DIRECTORY_SHIFT)];
    // Retirement clears PRESENT before its one range-wide TLB invalidation,
    // while keeping huge-leaf geometry until the frames can be reclaimed.
    if ((directory_entry.* & ENTRY_LARGE_PAGE) != 0) return directory_entry;
    if (!entryPresent(directory_entry.*)) return null;
    const page_table = tableFromEntry(directory_entry.*);
    return &page_table[tableIndex(virt_addr, PAGE_TABLE_SHIFT)];
}

pub fn setPageReadOnly(virt_addr: usize) void {
    const entry = lookupLeaf(getCurrentPageDirectory(), virt_addr) orelse return;
    if (!entryPresent(entry.*) or table64.isLargePage(entry.*)) return;
    publishCurrentLeafMutation(LeafInvalidation{}, entry, entry.* & ~ENTRY_WRITABLE, virt_addr) catch
        @panic("kernel permission change requires the BSP runtime owner");
}

pub const PagePermissions = struct {
    writable: bool,
    executable: bool,
    user: bool,
};

const OwnedUserTables = struct {
    fn table(entry: PageTableEntry) ?*PageTable {
        const address = directMapAddress(@intCast(entryAddress(entry))) orelse return null;
        return @ptrFromInt(address);
    }
};

pub fn ownedUserPagePermissions(space: *const UserAddressSpace, virtual_address: usize) ?PagePermissions {
    return ownedUserPagePermissionsWith(SharedUserTables, space.directory, virtual_address);
}

const SharedUserPageState = enum { absent, present, invalid };

// This authority-fed path never accepts generic borrowed leaves: demand paging
// first authenticates the exact live Table registration. The caller keeps the
// address space and backing quiescent until its one physical-alias copy ends.
pub fn prepareSharedPhysicalUserRange(
    space: *UserAddressSpace,
    virtual_start: usize,
    physical_start: u64,
    size_bytes: usize,
    write: bool,
    protection_key: u4,
) ?usize {
    return prepareSharedPhysicalUserRangeWith(SharedUserRangeMapping{ .space = space }, virtual_start, physical_start, size_bytes, write, protection_key);
}

fn prepareSharedPhysicalUserRangeWith(
    backend: anytype,
    virtual_start: usize,
    physical_start: u64,
    size_bytes: usize,
    write: bool,
    protection_key: u4,
) ?usize {
    if (size_bytes == 0 or protection_key != 0 or pageOffset(virtual_start) != physical_start & PAGE_OFFSET_MASK) return null;
    const end = std.math.add(usize, virtual_start, size_bytes) catch return null;
    const physical_end = std.math.add(u64, physical_start, size_bytes) catch return null;
    if (end > 0x0000_8000_0000_0000 or physical_end > MANAGED_PHYSICAL_BYTES) return null;
    const alias = backend.alias(physical_start, size_bytes, write) orelse return null;
    const first = virtual_start & ~@as(usize, PAGE_OFFSET_MASK);
    const physical_first = physical_start & ~@as(u64, PAGE_OFFSET_MASK);
    // Reject every forged late entry before the first allocation/publication.
    var address = first;
    while (address < end) : (address += PAGE_SIZE) {
        if (backend.state(address, physical_first + address - first, write, protection_key) == .invalid) return null;
    }
    address = first;
    while (address < end) : (address += PAGE_SIZE) {
        const physical = physical_first + address - first;
        if (backend.state(address, physical, write, protection_key) == .absent and !backend.map(address, physical)) return null;
    }
    // Mapping failure or a changed postcondition never exposes a payload alias.
    address = first;
    while (address < end) : (address += PAGE_SIZE) {
        if (backend.state(address, physical_first + address - first, write, protection_key) != .present) return null;
    }
    return alias;
}

fn sharedUserPageStateWith(
    comptime tables: type,
    directory: *PageDirectory,
    virtual_address: usize,
    expected_physical: u64,
    write: bool,
    protection_key: u4,
) SharedUserPageState {
    if (virtual_address >= 0x0000_8000_0000_0000 or expected_physical % PAGE_SIZE != 0 or
        expected_physical > MANAGED_PHYSICAL_BYTES - PAGE_SIZE or protection_key != 0) return .invalid;
    var current = directory;
    for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }) |shift| {
        const entry = current[tableIndex(virtual_address, shift)];
        if (!entryPresent(entry)) return if (entry == 0) .absent else .invalid;
        if (entryOwner(entry) != TABLE_OWNER_USER_PRIVATE or entry & ENTRY_USER == 0 or
            (write and entry & ENTRY_WRITABLE == 0) or entry & (ENTRY_LARGE_PAGE | ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE | ENTRY_GLOBAL | table64.PROTECTION_KEY_MASK) != 0 or
            entry & ~(@as(u64, 0x000F_FFFF_FFFF_FFFF) | table64.NO_EXECUTE) != 0 or
            entryAddress(entry) == 0 or entryAddress(entry) >= MANAGED_PHYSICAL_BYTES) return .invalid;
        current = tables.table(entry) orelse return .invalid;
    }
    const entry = current[tableIndex(virtual_address, PAGE_TABLE_SHIFT)];
    if (!entryPresent(entry)) return if (entry == 0) .absent else .invalid;
    if (entryOwner(entry) != PAGE_OWNER_BORROWED or entry & ENTRY_USER == 0 or
        (write and entry & ENTRY_WRITABLE == 0) or table64.isExecutable(entry) or
        entry & (ENTRY_LARGE_PAGE | ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE | ENTRY_GLOBAL) != 0 or
        entry & ~(@as(u64, 0x000F_FFFF_FFFF_FFFF) | table64.NO_EXECUTE | table64.PROTECTION_KEY_MASK) != 0 or
        table64.protectionKey(entry) != protection_key or entryAddress(entry) != expected_physical) return .invalid;
    return .present;
}

const SharedUserRangeMapping = struct {
    space: *UserAddressSpace,

    fn state(self: @This(), address: usize, physical: u64, write: bool, key: u4) SharedUserPageState {
        return sharedUserPageStateWith(SharedUserTables, self.space.directory, address, physical, write, key);
    }

    fn alias(_: @This(), physical: u64, bytes: usize, write: bool) ?usize {
        return mappedRamSpanForAccess(physical, bytes, write);
    }

    fn map(self: @This(), address: usize, physical: u64) bool {
        return mapSharedBorrowedPageWith(self, address, physical);
    }

    fn root(self: @This()) *PageDirectory {
        return self.space.directory;
    }

    fn allocate(_: @This()) ?u64 {
        return allocGeneralFrame();
    }

    fn optionalTable(_: @This(), entry: PageTableEntry) ?*PageTable {
        return SharedUserTables.table(entry);
    }

    fn publish(self: @This(), leaf: *PageTableEntry, value: PageTableEntry, address: usize) void {
        publishLeafMutation(LeafInvalidation{ .local = self.space.directory == getCurrentPageDirectory() }, leaf, value, address);
    }
};

const SharedUserTables = struct {
    fn table(entry: PageTableEntry) ?*PageTable {
        const physical = entryAddress(entry);
        // An owner tag cannot authorize a pointer into a sparse-map hole or a
        // reserved firmware frame. Allocated native frames have owned WB RAM
        // aliases; the caller's quiescence contract protects their lifetime.
        if (!allocated(physical)) return null;
        return OwnedUserTables.table(entry);
    }

    fn allocated(physical: usize) bool {
        return allocatedSpan(physical, PAGE_SIZE);
    }

    fn allocatedSpan(physical: usize, bytes: usize) bool {
        acquireFrameLock();
        defer releaseFrameLock();
        return allocatedPhysicalSpanWith(&physical_frames, physical, bytes);
    }
};

inline fn allocatedPhysicalSpanWith(allocator: anytype, physical: usize, bytes: usize) bool {
    if (physical >= MANAGED_PHYSICAL_BYTES or bytes > MANAGED_PHYSICAL_BYTES - physical) return false;
    // Check retained free ownership once for the whole span, rather than
    // rescanning up to 256 cached frames for each of a huge leaf's 512 pages.
    if (cachedFrameSpan(physical, bytes)) return false;
    var address = physical;
    while (address < physical + bytes) : (address += PAGE_SIZE) {
        if (!allocator.isAllocated(address)) return false;
    }
    return true;
}

fn mapSharedBorrowedPageWith(backend: anytype, address: usize, physical: u64) bool {
    var current = backend.root();
    for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }) |shift| {
        const entry = &current[tableIndex(address, shift)];
        if (entry.* == 0) {
            const frame = backend.allocate() orelse return false;
            const replacement = tableEntry(@intCast(frame), ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE, TABLE_OWNER_USER_PRIVATE);
            const table = backend.optionalTable(replacement) orelse return false;
            publishZeroedTable(entry, table, replacement);
        }
        // Existing parent permissions are never widened for a read copy.
        current = backend.optionalTable(entry.*) orelse return false;
    }
    const leaf = &current[tableIndex(address, PAGE_TABLE_SHIFT)];
    if (leaf.* != 0) return false;
    backend.publish(leaf, tableEntry(@intCast(physical), ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE | table64.NO_EXECUTE, PAGE_OWNER_BORROWED), address);
    return true;
}

fn ownedUserPagePermissionsWith(comptime tables: type, directory: *PageDirectory, virtual_address: usize) ?PagePermissions {
    var permissions: ?PagePermissions = null;
    var leaf_end: usize = undefined;
    if (!inspectOwnedUserPreparationPageIntoWith(tables, directory, virtual_address, false, &permissions, &leaf_end, null)) return null;
    return permissions;
}

// Distinguish genuinely absent slots from malformed/retired private backing.
// A rejected present hierarchy must never fall through to an unchecked mapper.
pub fn inspectOwnedUserPreparationPageInto(space: *const UserAddressSpace, virtual_address: usize, write: bool, out: *?PagePermissions, leaf_end: *usize) bool {
    return inspectOwnedUserPreparationPageIntoWith(SharedUserTables, space.directory, virtual_address, write, out, leaf_end, null);
}

fn inspectOwnedUserPreparationPageIntoWith(comptime tables: type, directory: *PageDirectory, virtual_address: usize, write: bool, out: *?PagePermissions, leaf_end: *usize, physical_out: ?*usize) bool {
    if (virtual_address >= 0x0000_8000_0000_0000) return false;
    var current = directory;
    var writable = true;
    var executable = true;
    for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }, 0..) |shift, level| {
        const entry = current[tableIndex(virtual_address, shift)];
        if (!entryPresent(entry)) {
            if (entry != 0 or !writable) return false;
            out.* = null;
            leaf_end.* = (virtual_address & ~PAGE_OFFSET_MASK) + PAGE_SIZE;
            return true;
        }
        if (entry & ENTRY_USER == 0 or
            entry & (ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE | ENTRY_GLOBAL) != 0 or
            entry & ~(@as(u64, 0x000F_FFFF_FFFF_FFFF) | table64.NO_EXECUTE | table64.PROTECTION_KEY_MASK) != 0) return false;
        writable = writable and (entry & ENTRY_WRITABLE) != 0;
        executable = executable and table64.isExecutable(entry);
        if (write and !writable and !table64.isLargePage(entry)) return false;
        if (table64.isLargePage(entry)) {
            if (level != 2) return false;
            const permissions = ownedLeafPermissions(entry, writable, executable, @intCast(LARGE_2M_PAGE_SIZE)) orelse return false;
            // Permission promotion is defined only for nonexecuting 4 KiB
            // copies; existing writable huge data and readable code remain valid.
            if ((write and (!permissions.writable or table64.isExecutable(entry))) or
                !tables.allocatedSpan(entryAddress(entry), @intCast(LARGE_2M_PAGE_SIZE))) return false;
            out.* = permissions;
            leaf_end.* = (virtual_address & ~(@as(usize, LARGE_2M_PAGE_SIZE) - 1)) + LARGE_2M_PAGE_SIZE;
            if (physical_out) |physical| physical.* = entryAddress(entry) + virtual_address % LARGE_2M_PAGE_SIZE;
            return true;
        }
        if (entryOwner(entry) != TABLE_OWNER_USER_PRIVATE or table64.protectionKey(entry) != 0 or
            entryAddress(entry) == 0 or entryAddress(entry) >= MANAGED_PHYSICAL_BYTES) return false;
        current = tables.table(entry) orelse return false;
    }
    const entry = current[tableIndex(virtual_address, PAGE_TABLE_SHIFT)];
    if (!entryPresent(entry)) {
        if (entry != 0 or !writable) return false;
        out.* = null;
        leaf_end.* = (virtual_address & ~PAGE_OFFSET_MASK) + PAGE_SIZE;
        return true;
    }
    if (entry & (ENTRY_LARGE_PAGE | ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE | ENTRY_GLOBAL) != 0 or
        entry & ~(@as(u64, 0x000F_FFFF_FFFF_FFFF) | table64.NO_EXECUTE | table64.PROTECTION_KEY_MASK) != 0) return false;
    const permissions = ownedLeafPermissions(entry, writable, executable, PAGE_SIZE) orelse return false;
    if ((write and table64.isExecutable(entry)) or !tables.allocatedSpan(entryAddress(entry), PAGE_SIZE)) return false;
    out.* = permissions;
    leaf_end.* = (virtual_address & ~PAGE_OFFSET_MASK) + PAGE_SIZE;
    if (physical_out) |physical| physical.* = entryAddress(entry) + pageOffset(virtual_address);
    return true;
}

pub const WritableUserSegment = struct { address: usize, bytes: usize };

// A processing dispatch lease pins the root and all mapping metadata. Resolve
// the complete bounded output before the broker writes anything; no deferred
// page-table mutation or retained alias is permitted across the commit.
pub fn resolveOwnedUserOutputInto(space: *const UserAddressSpace, virtual_start: usize, bytes: usize, out: *[2]WritableUserSegment, count_out: *u8) bool {
    if (comptime builtin.target.os.tag != .freestanding) return false;
    if (!@import("../smp.zig").isRuntimeOwner() or x86.interruptsEnabled() or !kernelAddressSpaceActive()) return false;
    const Backend = struct {
        fn alias(_: *@This(), physical: usize, length: usize) ?usize {
            return mappedRamSpanForAccess(physical, length, true);
        }
    };
    var backend = Backend{};
    return resolveOwnedUserOutputIntoWith(OwnedOutputTables, &backend, space.directory, virtual_start, bytes, out, count_out);
}

const OwnedOutputTables = struct {
    fn table(entry: PageTableEntry) ?*PageTable {
        const physical = entryAddress(entry);
        if (!allocatedSpan(physical, PAGE_SIZE)) return null;
        return @ptrFromInt(mappedRamSpanForAccess(physical, PAGE_SIZE, false) orelse return null);
    }

    inline fn allocatedSpan(physical: usize, bytes: usize) bool {
        acquireFrameLock();
        defer releaseFrameLock();
        return allocatedPhysicalSpanWith(&physical_frames, physical, bytes);
    }
};

fn resolveOwnedUserOutputIntoWith(comptime tables: type, backend: anytype, directory: *PageDirectory, virtual_start: usize, bytes: usize, out: *[2]WritableUserSegment, count_out: *u8) bool {
    if (bytes == 0 or bytes > 88 or virtual_start < PAGE_SIZE) return false;
    const end = std.math.add(usize, virtual_start, bytes) catch return false;
    if (end > 0x0000_8000_0000_0000) return false;
    var segments: [2]WritableUserSegment = undefined;
    var count: u8 = 0;
    var address = virtual_start;
    while (address < end) {
        var permissions: ?PagePermissions = null;
        var leaf_end: usize = undefined;
        var physical: usize = undefined;
        if (!inspectOwnedUserPreparationPageIntoWith(tables, directory, address, true, &permissions, &leaf_end, &physical) or
            permissions == null or !permissions.?.writable or count == segments.len) return false;
        const length = @min(end - address, leaf_end - address);
        segments[count] = .{ .address = backend.alias(physical, length) orelse return false, .bytes = length };
        count += 1;
        address += length;
    }
    // Only the live prefix is published; failure leaves both outputs intact.
    @memcpy(out[0..count], segments[0..count]);
    count_out.* = count;
    return true;
}

test "owned output resolution preflights late leaves and aliases before publishing any destination" {
    const Model = WritePreparationTestPaging.Model;
    const Backend = struct {
        model: *Model,
        denied: ?usize = null,
        aliases: usize = 0,

        fn alias(self: *@This(), physical: usize, bytes: usize) ?usize {
            self.aliases += 1;
            if (self.denied == physical / PAGE_SIZE or physical / PAGE_SIZE >= self.model.payload.len or
                bytes > PAGE_SIZE - physical % PAGE_SIZE) return null;
            return @intFromPtr(&self.model.payload[physical / PAGE_SIZE]) + physical % PAGE_SIZE;
        }
    };
    var model: Model = undefined;
    try model.init();
    defer model.deinit();
    for (0..3) |index| model.leaf(Model.base + index * PAGE_SIZE).* |= ENTRY_WRITABLE;
    var backend = Backend{ .model = &model };
    const start = Model.base + PAGE_SIZE - 16;
    const sentinel = [_]WritableUserSegment{ .{ .address = 123, .bytes = 456 }, .{ .address = 789, .bytes = 101 } };
    var segments = sentinel;
    var count: u8 = 7;
    try std.testing.expect(resolveOwnedUserOutputIntoWith(Model.Tables, &backend, model.space.directory, start, 32, &segments, &count));
    try std.testing.expectEqual(@as(u8, 2), count);
    try std.testing.expectEqual(@as(usize, 16), segments[0].bytes);
    try std.testing.expectEqual(@intFromPtr(&model.payload[model.data[0] / PAGE_SIZE]) + PAGE_SIZE - 16, segments[0].address);
    try std.testing.expectEqual(@intFromPtr(&model.payload[model.data[1] / PAGE_SIZE]), segments[1].address);
    const late = model.leaf(Model.base + PAGE_SIZE);
    const original = late.*;
    const malformed = [_]PageTableEntry{
        0,                              original & ~ENTRY_WRITABLE,                       original & ~ENTRY_USER,  original & ~table64.NO_EXECUTE,
        original | ENTRY_CACHE_DISABLE, original | ENTRY_WRITE_THROUGH,                   original | ENTRY_GLOBAL, original | ENTRY_LARGE_PAGE,
        original | (@as(u64, 1) << 55), table64.withOwner(original, PAGE_OWNER_BORROWED),
    };
    for (malformed) |entry| {
        late.* = entry;
        segments = sentinel;
        count = 7;
        try std.testing.expect(!resolveOwnedUserOutputIntoWith(Model.Tables, &backend, model.space.directory, start, 32, &segments, &count));
        try std.testing.expectEqualDeep(sentinel, segments);
        try std.testing.expectEqual(@as(u8, 7), count);
    }
    late.* = original;
    backend.denied = model.data[1] / PAGE_SIZE;
    segments = sentinel;
    count = 7;
    try std.testing.expect(!resolveOwnedUserOutputIntoWith(Model.Tables, &backend, model.space.directory, start, 32, &segments, &count));
    try std.testing.expectEqualDeep(sentinel, segments);
    try std.testing.expectEqual(@as(u8, 7), count);
    backend.denied = null;
    try model.frames.release(.{ .base = model.data[1], .count = 1 });
    try std.testing.expect(!resolveOwnedUserOutputIntoWith(Model.Tables, &backend, model.space.directory, start, 32, &segments, &count));
    for (&model.payload) |page| try std.testing.expectEqualSlices(u8, &@as([PAGE_SIZE]u8, @splat(0xa5)), &page);

    // Every parent is admitted before its target table is followed. An NX
    // parent cannot authorize an executable leaf for a supervisor output.
    var current = model.space.directory;
    for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }) |shift| {
        const parent = &current[tableIndex(Model.base, shift)];
        const saved = parent.*;
        for ([_]PageTableEntry{ saved & ~ENTRY_USER, saved & ~ENTRY_WRITABLE, saved | ENTRY_CACHE_DISABLE, saved | ENTRY_WRITE_THROUGH, saved | ENTRY_GLOBAL, saved | ENTRY_LARGE_PAGE, saved | (@as(u64, 1) << 55), table64.withOwner(saved, TABLE_OWNER_KERNEL_DYNAMIC), tableEntry(15 * PAGE_SIZE, ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE, TABLE_OWNER_USER_PRIVATE) }) |entry| {
            parent.* = entry;
            const aliases_before = backend.aliases;
            try std.testing.expect(!resolveOwnedUserOutputIntoWith(Model.Tables, &backend, model.space.directory, Model.base, 1, &segments, &count));
            try std.testing.expectEqual(aliases_before, backend.aliases);
            try std.testing.expectEqualDeep(sentinel, segments);
        }
        parent.* = saved;
        current = Model.Tables.table(saved).?;
    }
    for ([_]usize{ 0, 0x0000_8000_0000_0000, std.math.maxInt(usize) - 15 }) |address|
        try std.testing.expect(!resolveOwnedUserOutputIntoWith(Model.Tables, &backend, model.space.directory, address, 32, &segments, &count));
    try std.testing.expect(!resolveOwnedUserOutputIntoWith(Model.Tables, &backend, model.space.directory, Model.base, 89, &segments, &count));
}

test "owned output resolution admits a complete writable huge allocation once and rejects freed backing" {
    const Model = WritePreparationTestPaging.Model;
    const Backend = struct {
        backing: [88]u8 = @splat(0xaa),
        fn alias(self: *@This(), _: usize, bytes: usize) ?usize {
            if (bytes > self.backing.len) return null;
            return @intFromPtr(&self.backing);
        }
    };
    var model: Model = undefined;
    try model.init();
    defer model.deinit();
    try model.installHuge();
    var backend = Backend{};
    var segments: [2]WritableUserSegment = undefined;
    var count: u8 = 0;
    try std.testing.expect(resolveOwnedUserOutputIntoWith(Model.Tables, &backend, model.space.directory, Model.base + 17, 88, &segments, &count));
    try std.testing.expectEqual(@as(u8, 1), count);
    try std.testing.expectEqual(@as(usize, 1), model.huge_span_queries);
    try model.frames.release(.{ .base = LARGE_2M_PAGE_SIZE + 511 * PAGE_SIZE, .count = 1 });
    const before = segments;
    try std.testing.expect(!resolveOwnedUserOutputIntoWith(Model.Tables, &backend, model.space.directory, Model.base + 17, 88, &segments, &count));
    try std.testing.expectEqualDeep(before, segments);
}

fn ownedLeafPermissions(entry: PageTableEntry, writable: bool, executable: bool, leaf_size: usize) ?PagePermissions {
    if (!entryPresent(entry) or entryOwner(entry) != PAGE_OWNER_USER_PRIVATE or (entry & ENTRY_USER) == 0) return null;
    const physical = entryAddress(entry);
    if (physical % leaf_size != 0 or physical > MANAGED_PHYSICAL_BYTES - leaf_size) return null;
    return .{
        .writable = writable and (entry & ENTRY_WRITABLE) != 0,
        .executable = executable and table64.isExecutable(entry),
        .user = true,
    };
}

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
    publishCurrentLeafMutation(LeafInvalidation{}, entry, 0, virt_addr) catch
        @panic("kernel unmap requires the BSP runtime owner");
    return true;
}

/// The owner must stop all users of this borrowed range before retirement and
/// may release its backing frames only after this synchronous call returns.
pub fn unmapBorrowedKernelRange(virtual_start: usize, size_bytes: usize) BorrowedKernelUnmapError!void {
    try requireKernelMappingOwner();
    return retireBorrowedKernelRange(KernelBorrowedRange{}, virtual_start, size_bytes);
}

const KernelBorrowedRange = struct {
    fn lookup(_: @This(), address: usize) ?*PageTableEntry {
        return lookupLeaf(kernelPageDirectory(), address);
    }

    fn invalidateLocal(_: @This(), address: usize) void {
        invalidate_page(address);
    }

    fn invalidateRemoteKernel(_: @This()) void {
        if (remote_kernel_shootdown) |shootdown| shootdown();
    }
};

fn retireBorrowedKernelRange(backend: anytype, virtual_start: usize, size: usize) BorrowedKernelUnmapError!void {
    if (pageOffset(virtual_start) != 0 or size == 0 or size % PAGE_SIZE != 0)
        return error.InvalidRange;
    const end = std.math.add(usize, virtual_start, size) catch return error.AddressOverflow;
    if (!table64.isCanonicalVirtualAddress(virtual_start) or
        !table64.isCanonicalVirtualAddress(end - 1) or
        virtual_start >> 47 != (end - 1) >> 47)
        return error.InvalidRange;

    var address = virtual_start;
    // A collision or missing leaf must leave the entire range unchanged.
    while (address < end) : (address += PAGE_SIZE) {
        const entry = backend.lookup(address) orelse return error.MappingNotBorrowed;
        if (!entryPresent(entry.*) or table64.isLargePage(entry.*) or
            entryOwner(entry.*) != PAGE_OWNER_BORROWED or
            (entry.* & (ENTRY_GLOBAL | ENTRY_USER)) != ENTRY_GLOBAL)
            return error.MappingNotBorrowed;
    }
    address = virtual_start;
    while (address < end) : (address += PAGE_SIZE) {
        @atomicStore(PageTableEntry, backend.lookup(address).?, 0, .release);
    }
    address = virtual_start;
    while (address < end) : (address += PAGE_SIZE) backend.invalidateLocal(address);
    backend.invalidateRemoteKernel();
}

test "borrowed kernel range retirement rolls back collisions and retains frames through one acknowledged barrier" {
    const Allocator = frame_allocator.Fixed(8 * PAGE_SIZE, PAGE_SIZE);
    const Model = struct {
        const base = virtual_layout.native_stacks.base;
        entries: [4]PageTableEntry,
        frames: *Allocator,
        run: FrameRun,
        local_count: usize = 0,
        remote_count: usize = 0,
        acknowledged: bool = false,
        valid: bool = true,

        fn lookup(self: *@This(), address: usize) ?*PageTableEntry {
            if (address < base or address - base >= self.entries.len * PAGE_SIZE) return null;
            return &self.entries[(address - base) / PAGE_SIZE];
        }

        fn invalidateLocal(self: *@This(), address: usize) void {
            if (address != base + self.local_count * PAGE_SIZE) self.valid = false;
            for (&self.entries) |*entry| {
                if (@atomicLoad(PageTableEntry, entry, .acquire) != 0) self.valid = false;
            }
            if (self.remote_count != 0) self.valid = false;
            self.local_count += 1;
        }

        fn invalidateRemoteKernel(self: *@This()) void {
            if (self.local_count != self.entries.len) self.valid = false;
            for (self.entries) |entry| {
                if (entry != 0) self.valid = false;
            }
            for (0..self.run.count) |index| {
                if (!self.frames.isAllocated(self.run.base + index * PAGE_SIZE)) self.valid = false;
            }
            self.remote_count += 1;
            self.acknowledged = true;
        }
    };
    var storage: Allocator.Storage = undefined;
    var frames = Allocator.init(&storage);
    const run = frames.allocate(4).?;
    var model = Model{ .entries = undefined, .frames = &frames, .run = run };
    for (&model.entries, 0..) |*entry, index|
        entry.* = tableEntry(@intCast(run.base + index * PAGE_SIZE), ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_GLOBAL | table64.NO_EXECUTE, PAGE_OWNER_BORROWED);
    const original = model.entries;
    for ([_]PageTableEntry{
        0,
        original[1] | ENTRY_USER,
        original[1] | ENTRY_LARGE_PAGE,
        original[1] & ~ENTRY_GLOBAL,
        table64.withOwner(original[1], PAGE_OWNER_USER_PRIVATE),
    }) |collision| {
        model.entries[1] = collision;
        const before = model.entries;
        try std.testing.expectError(error.MappingNotBorrowed, retireBorrowedKernelRange(&model, Model.base, 4 * PAGE_SIZE));
        try std.testing.expectEqualDeep(before, model.entries);
        try std.testing.expectEqual(@as(u32, 4), frames.stats().allocated);
        try std.testing.expectEqual(@as(usize, 0), model.local_count);
        try std.testing.expectEqual(@as(usize, 0), model.remote_count);
    }
    model.entries = original;
    try std.testing.expectError(error.MappingNotBorrowed, retireBorrowedKernelRange(&model, Model.base, 5 * PAGE_SIZE));
    try std.testing.expectEqualDeep(original, model.entries);
    try std.testing.expectError(error.InvalidRange, retireBorrowedKernelRange(&model, Model.base + 1, PAGE_SIZE));
    try std.testing.expectError(error.InvalidRange, retireBorrowedKernelRange(&model, Model.base, 0));
    try std.testing.expectError(error.InvalidRange, retireBorrowedKernelRange(&model, Model.base, PAGE_SIZE + 1));
    try std.testing.expectError(error.InvalidRange, retireBorrowedKernelRange(&model, 0x0000_7FFF_FFFF_F000, 2 * PAGE_SIZE));
    try std.testing.expectError(error.AddressOverflow, retireBorrowedKernelRange(&model, std.math.maxInt(usize) & ~PAGE_OFFSET_MASK, 2 * PAGE_SIZE));
    try std.testing.expectEqualDeep(original, model.entries);
    try retireBorrowedKernelRange(&model, Model.base, 4 * PAGE_SIZE);
    try std.testing.expect(model.valid and model.acknowledged);
    try std.testing.expectEqual(@as(usize, 4), model.local_count);
    try std.testing.expectEqual(@as(usize, 1), model.remote_count);
    try std.testing.expectEqual(@as(u32, 4), frames.stats().allocated);
    try frames.release(run);
    try std.testing.expectEqual(@as(u32, 0), frames.stats().allocated);
    const reused = frames.allocate(4).?;
    try std.testing.expectEqualDeep(run, reused);
}

test "private context retirement reaches remote CPUs independently of initiating PCIDE mode" {
    const Model = struct {
        identifiers: [2]u16 = @splat(0),
        local_count: usize = 0,
        reload_count: usize = 0,
        remote_count: usize = 0,

        fn invalidatePcid(self: *@This(), identifier: u16) void {
            self.identifiers[0] = identifier;
            self.local_count += 1;
        }

        fn reloadCurrentRoot(self: *@This()) void {
            self.reload_count += 1;
        }

        fn invalidateRemote(self: *@This(), identifier: u16) void {
            self.identifiers[1] = identifier;
            self.remote_count += 1;
        }
    };
    for ([_]bool{ false, true }) |identifiers_enabled| {
        for ([_]bool{ false, true }) |active| {
            var model = Model{};
            invalidateUserContextWith(&model, 37, identifiers_enabled, active);
            try std.testing.expectEqual(@as(usize, @intFromBool(identifiers_enabled)), model.local_count);
            try std.testing.expectEqual(@as(usize, @intFromBool(!identifiers_enabled and active)), model.reload_count);
            try std.testing.expectEqual(@as(usize, 1), model.remote_count);
            try std.testing.expectEqual(@as(u16, 37), model.identifiers[1]);
            if (identifiers_enabled) try std.testing.expectEqual(@as(u16, 37), model.identifiers[0]);
        }
    }
}

pub fn createUserAddressSpace() UserAddressSpaceCreateError!UserAddressSpace {
    const pml4_phys = allocGeneralFrame() orelse return error.OutOfMemory;
    const pml4 = tableAtPhysical(pml4_phys);
    zeroTable(pml4);

    // Task roots inherit only the supervisor upper half. Private lower-half
    // tables are allocated lazily, without importing the temporary AP bridge.
    inheritKernelMappings(kernelPageDirectory(), pml4);
    const pcid = tryAllocProcessContext() orelse {
        releasePhysicalFrames(pml4_phys, 1) catch haltPagingFailure(.corrupt_pml4_allocation_accounting);
        return error.ProcessContextExhausted;
    };
    return .{
        .directory = pml4,
        .pcid = pcid,
        .switch_cr3 = addressSpaceCr3(pml4_phys, pcid),
    };
}

fn inheritKernelMappings(kernel: *const PageDirectory, task: *PageDirectory) void {
    for (kernel[256..], task[256..]) |kernel_entry, *task_entry| {
        task_entry.* = kernel_entry;
    }
}

inline fn ensureOwnedLeaf(space: *UserAddressSpace, virtual_address: usize) UserMapError!*PageTableEntry {
    const address: usize = virtual_address;
    const pdpt = try ensureChildTable(space.directory, tableIndex(address, PML4_SHIFT), true, TABLE_OWNER_USER_PRIVATE);
    const page_directory = try ensureChildTable(pdpt, tableIndex(address, PDPT_SHIFT), true, TABLE_OWNER_USER_PRIVATE);
    const page_table = try ensureChildTable(page_directory, tableIndex(address, PAGE_DIRECTORY_SHIFT), true, TABLE_OWNER_USER_PRIVATE);
    return &page_table[tableIndex(address, PAGE_TABLE_SHIFT)];
}

const OwnedUserPageMapping = struct {
    space: *UserAddressSpace,

    inline fn validate(self: @This(), address: usize) UserMapError!void {
        return validateOwnedMappingSlot(self.space, address);
    }

    inline fn mapHuge(self: @This(), address: usize, permissions: UserPermissions) UserMapError!bool {
        return directorySlotFreeForHugePage(self.space, address) and
            try mapOwnedUserHugePage(self.space, address, permissions);
    }

    inline fn mapSmall(self: @This(), address: usize, permissions: UserPermissions) UserMapError!void {
        return initializeOwnedUserPage(self, address, permissions, null);
    }

    inline fn leaf(self: @This(), address: usize) UserMapError!*PageTableEntry {
        return ensureOwnedLeaf(self.space, address);
    }

    inline fn allocate(_: @This()) ?frame_allocator.PhysicalAddress {
        return allocGeneralFrame();
    }

    inline fn bytes(_: @This(), physical: frame_allocator.PhysicalAddress) *[PAGE_SIZE]u8 {
        return bytesAtPhysical(physical)[0..PAGE_SIZE];
    }
};

inline fn initializeOwnedUserPage(
    backend: anytype,
    virtual_address: usize,
    permissions: UserPermissions,
    source: ?*const [PAGE_SIZE]u8,
) UserMapError!void {
    if (permissions.write_through or permissions.cache_disabled) return error.InvalidRange;
    const page_entry = try backend.leaf(virtual_address);
    if (entryPresent(page_entry.*)) return error.AlreadyMapped;
    const page_phys = backend.allocate() orelse return error.OutOfMemory;
    const destination = backend.bytes(page_phys);
    if (source) |snapshot| {
        @memcpy(destination, snapshot);
    } else {
        @memset(destination, 0);
    }
    var flags: u32 = PAGE_PRESENT | PAGE_USER;
    if (permissions.writable) flags |= PAGE_WRITABLE;
    if (permissions.write_through) flags |= PAGE_WRITE_THROUGH;
    if (permissions.cache_disabled) flags |= PAGE_CACHE_DISABLE;
    const entry_flags = table64.withProtectionKey(
        table64.withExecutePermission(leafFlags(flags, false), permissions.executable),
        0,
    );
    @atomicStore(PageTableEntry, page_entry, tableEntry(@intCast(page_phys), entry_flags, PAGE_OWNER_USER_PRIVATE), .release);
}

fn ensureOwnedDirectorySlot(space: *UserAddressSpace, virtual_address: usize) UserMapError!*PageTableEntry {
    const address: usize = virtual_address;
    const pdpt = try ensureChildTable(space.directory, tableIndex(address, PML4_SHIFT), true, TABLE_OWNER_USER_PRIVATE);
    const page_directory = try ensureChildTable(pdpt, tableIndex(address, PDPT_SHIFT), true, TABLE_OWNER_USER_PRIVATE);
    return &page_directory[tableIndex(address, PAGE_DIRECTORY_SHIFT)];
}

fn directorySlotFreeForHugePage(space: *const UserAddressSpace, virtual_address: usize) bool {
    const address: usize = virtual_address;
    const pml4_entry = space.directory[tableIndex(address, PML4_SHIFT)];
    if (!entryPresent(pml4_entry)) return true;
    const pdpt = tableFromEntry(pml4_entry);
    const pdpt_entry = pdpt[tableIndex(address, PDPT_SHIFT)];
    if (!entryPresent(pdpt_entry) or table64.isLargePage(pdpt_entry)) return !entryPresent(pdpt_entry);
    const page_directory = tableFromEntry(pdpt_entry);
    const directory_entry = page_directory[tableIndex(address, PAGE_DIRECTORY_SHIFT)];
    return !entryPresent(directory_entry);
}

fn mapOwnedUserHugePage(
    space: *UserAddressSpace,
    virtual_address: usize,
    permissions: UserPermissions,
) UserMapError!bool {
    const directory_entry = try ensureOwnedDirectorySlot(space, virtual_address);
    if (entryPresent(directory_entry.*)) return error.AlreadyMapped;
    const run = allocGeneralAlignedFrames(LARGE_2M_FRAME_COUNT, LARGE_2M_FRAME_COUNT) orelse return false;
    const entry = ownedUserHugeLeaf(run.base, permissions) catch |err| {
        releasePhysicalFrames(run.base, run.count) catch
            haltPagingFailure(.corrupt_rejected_huge_page_allocation_accounting);
        return err;
    };
    const kernel_alias = bytesAtPhysical(run.base);
    @memset(kernel_alias[0..LARGE_2M_PAGE_SIZE], 0);
    @atomicStore(PageTableEntry, directory_entry, entry, .release);
    return true;
}

fn ownedUserHugeLeaf(physical: frame_allocator.PhysicalAddress, permissions: UserPermissions) UserMapError!PageTableEntry {
    // Huge PDEs require their physical base to match their 2 MiB geometry;
    // ordinary contiguous frame allocation guarantees only 4 KiB alignment.
    if (permissions.write_through or permissions.cache_disabled) return error.InvalidRange;
    if (physical % LARGE_2M_PAGE_SIZE != 0 or !table64.physicalAddressFits(@intCast(physical))) return error.InvalidRange;
    var flags: u32 = PAGE_PRESENT | PAGE_USER;
    if (permissions.writable) flags |= PAGE_WRITABLE;
    if (permissions.write_through) flags |= PAGE_WRITE_THROUGH;
    if (permissions.cache_disabled) flags |= PAGE_CACHE_DISABLE;
    const entry_flags = table64.withProtectionKey(
        table64.withExecutePermission(leafFlags(flags, false), permissions.executable) | ENTRY_LARGE_PAGE,
        0,
    );
    return tableEntry(@intCast(physical), entry_flags, PAGE_OWNER_USER_PRIVATE);
}

const LARGE_2M_FRAME_COUNT: u32 = @intCast(LARGE_2M_PAGE_SIZE / PAGE_SIZE);

fn validateOwnedMappingSlot(space: *const UserAddressSpace, virtual_address: usize) UserMapError!void {
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
    if (entryOwner(directory_entry) != TABLE_OWNER_USER_PRIVATE and
        entryOwner(directory_entry) != PAGE_OWNER_USER_PRIVATE)
        return error.KernelMappingCollision;
    if (table64.isLargePage(directory_entry)) return error.AlreadyMapped;

    const page_table = tableFromEntry(directory_entry);
    if (entryPresent(page_table[tableIndex(address, PAGE_TABLE_SHIFT)])) return error.AlreadyMapped;
}

pub fn mapOwnedUserRange(
    space: *UserAddressSpace,
    virtual_start: usize,
    size_bytes: usize,
    permissions: UserPermissions,
) UserMapError!void {
    return mapOwnedUserRangeWith(OwnedUserPageMapping{ .space = space }, virtual_start, size_bytes, permissions);
}

inline fn mapOwnedUserRangeWith(
    backend: anytype,
    virtual_start: usize,
    size_bytes: usize,
    permissions: UserPermissions,
) UserMapError!void {
    if (permissions.write_through or permissions.cache_disabled) return error.InvalidRange;
    if (pageOffset(virtual_start) != 0 or size_bytes == 0) return error.InvalidRange;
    if (permissions.writable and permissions.executable) return error.WritableExecutable;

    const mapped_size = try checkedUserMappedSize(virtual_start, size_bytes);

    var offset: usize = 0;
    while (offset < mapped_size) : (offset += PAGE_SIZE) {
        try backend.validate(virtual_start + offset);
    }

    offset = 0;
    while (offset < mapped_size) {
        const virtual_address = virtual_start + offset;
        const remaining = mapped_size - offset;
        if (USES_RUNTIME_2M_PAGES and
            remaining >= LARGE_2M_PAGE_SIZE and
            (virtual_address & @as(usize, @intCast(LARGE_2M_PAGE_SIZE - 1))) == 0 and
            try backend.mapHuge(virtual_address, permissions))
        {
            offset += @intCast(LARGE_2M_PAGE_SIZE);
            continue;
        }

        // Preflight already admitted the complete range. The initializer still
        // validates private ancestors and rejects a present leaf before allocation.
        try backend.mapSmall(virtual_address, permissions);
        offset += PAGE_SIZE;
    }
}

/// Materialize one private snapshot without first clearing the frame or exposing
/// a present leaf before the complete source page has been copied.
pub fn mapOwnedUserPageFromPhysical(
    space: *UserAddressSpace,
    virtual_start: usize,
    physical_base: u64,
    permissions: UserPermissions,
) UserMapError!void {
    if (permissions.write_through or permissions.cache_disabled) return error.InvalidRange;
    _ = try checkedUserMappedSize(virtual_start, PAGE_SIZE);
    if (permissions.writable and permissions.executable) return error.WritableExecutable;
    // Validate the entire source page before allocating frames or page tables.
    if (physical_base % PAGE_SIZE != 0 or physical_base > MANAGED_PHYSICAL_BYTES - PAGE_SIZE) return error.InvalidRange;
    const source: *const [PAGE_SIZE]u8 = bytesAtPhysical(physical_base)[0..PAGE_SIZE];
    try validateOwnedMappingSlot(space, virtual_start);
    return initializeOwnedUserPage(OwnedUserPageMapping{ .space = space }, virtual_start, permissions, source);
}

fn checkedUserMappedSize(virtual_start: usize, size_bytes: usize) UserMapError!usize {
    if (pageOffset(virtual_start) != 0 or size_bytes == 0) return error.InvalidRange;
    const padded_size = std.math.add(usize, size_bytes, PAGE_SIZE - 1) catch return error.AddressOverflow;
    const mapped_size = padded_size & ~@as(usize, PAGE_SIZE - 1);
    const mapped_end = std.math.add(usize, virtual_start, mapped_size) catch return error.AddressOverflow;
    if (mapped_end > 0x0000_8000_0000_0000) return error.InvalidRange;
    return mapped_size;
}

pub fn validateUserRangeAvailable(space: *const UserAddressSpace, virtual_start: usize, size_bytes: usize) UserMapError!void {
    const size = try checkedUserMappedSize(virtual_start, size_bytes);
    var offset: usize = 0;
    while (offset < size) : (offset += PAGE_SIZE) {
        try validateOwnedMappingSlot(space, virtual_start + offset);
    }
}

/// Reclaim one task's pages without destroying the page tables its group shares.
/// Callers must own the entire range, including any huge leaves it contains.
pub fn releaseUserRange(space: *const UserAddressSpace, virtual_start: usize, size_bytes: usize) UserMapError!void {
    const size = try checkedUserMappedSize(virtual_start, size_bytes);
    acquireFrameLock();
    defer releaseFrameLock();
    return retireUserRange(UserRangeRetirement{ .space = space }, virtual_start, size);
}

const UserRangeRetirement = struct {
    space: *const UserAddressSpace,

    fn lookup(self: @This(), address: usize) ?*PageTableEntry {
        return lookupLeaf(self.space.directory, address);
    }

    fn invalidate(self: @This()) void {
        invalidateUserContext(self.space);
    }

    fn release(_: @This(), physical: frame_allocator.PhysicalAddress, count: u32) void {
        releasePhysicalFramesLocked(physical, count) catch
            haltPagingFailure(.corrupt_retired_user_range_accounting);
    }
};

fn userLeafSize(entry: PageTableEntry) usize {
    return if ((entry & ENTRY_LARGE_PAGE) != 0) @intCast(LARGE_2M_PAGE_SIZE) else PAGE_SIZE;
}

fn retireUserRange(backend: anytype, virtual_start: usize, size: usize) UserMapError!void {
    const end = virtual_start + size;
    var address = virtual_start;
    // Validate first: a rejected range must leave all mappings intact.
    while (address < end) {
        const entry = backend.lookup(address) orelse {
            address += PAGE_SIZE;
            continue;
        };
        if (!entryPresent(entry.*)) {
            address += PAGE_SIZE;
            continue;
        }
        if ((entry.* & ENTRY_USER) == 0 or
            (entryOwner(entry.*) != PAGE_OWNER_BORROWED and entryOwner(entry.*) != PAGE_OWNER_USER_PRIVATE))
            return error.KernelMappingCollision;
        const leaf_size = userLeafSize(entry.*);
        if (address % leaf_size != 0 or end - address < leaf_size) return error.InvalidRange;
        address += leaf_size;
    }

    var retired_any = false;
    address = virtual_start;
    while (address < end) {
        const entry = backend.lookup(address) orelse {
            address += PAGE_SIZE;
            continue;
        };
        if (!entryPresent(entry.*)) {
            address += PAGE_SIZE;
            continue;
        }
        const old = entry.*;
        const retired_owner: u3 = if (entryOwner(old) == PAGE_OWNER_USER_PRIVATE)
            PAGE_OWNER_RETIRED_PRIVATE
        else
            PAGE_OWNER_RETIRED_BORROWED;
        @atomicStore(PageTableEntry, entry, table64.withOwner(old & ~ENTRY_PRESENT, retired_owner), .release);
        retired_any = true;
        address += userLeafSize(old);
    }
    if (!retired_any) return;

    // One flush retires the complete range. No frame can re-enter the allocator
    // until every remote CPU has acknowledged this invalidation.
    backend.invalidate();
    address = virtual_start;
    while (address < end) {
        const entry = backend.lookup(address) orelse {
            address += PAGE_SIZE;
            continue;
        };
        const old = entry.*;
        const owner = entryOwner(old);
        if (owner != PAGE_OWNER_RETIRED_PRIVATE and owner != PAGE_OWNER_RETIRED_BORROWED) {
            address += PAGE_SIZE;
            continue;
        }
        const leaf_size = userLeafSize(old);
        entry.* = 0;
        if (owner == PAGE_OWNER_RETIRED_PRIVATE) {
            backend.release(@intCast(entryAddress(old)), @intCast(leaf_size / PAGE_SIZE));
        }
        address += leaf_size;
    }
}

test "user mapping bounds reject alignment overflow and noncanonical ranges" {
    try std.testing.expectError(error.AddressOverflow, checkedUserMappedSize(0x4000_0000, std.math.maxInt(usize)));
    try std.testing.expectError(error.InvalidRange, checkedUserMappedSize(0x0000_8000_0000_0000, PAGE_SIZE));
    try std.testing.expectError(error.InvalidRange, checkedUserMappedSize(0x4000_0000, 0));
    try std.testing.expectEqual(@as(usize, PAGE_SIZE * 2), try checkedUserMappedSize(0x4000_0000, PAGE_SIZE + 1));
    try std.testing.expectEqual(@as(usize, PAGE_SIZE), try checkedUserMappedSize(0x0000_7fff_ffff_f000, PAGE_SIZE));
}

const OwnedRangeTestBackend = if (builtin.is_test) struct {
    const base: usize = 0x4000_0000;
    const capacity = 1025;
    entries: [capacity]PageTableEntry = @splat(0),
    frame: [PAGE_SIZE]u8 = @splat(0xA5),
    preflight_calls: usize = 0,
    small_walks: usize = 0,
    huge_attempts: usize = 0,
    huge_mappings: usize = 0,
    allocated_frames: usize = 0,
    frame_budget: usize = capacity,
    allow_huge: bool = true,
    foreign_slot: ?usize = null,
    fail_leaf_slot: ?usize = null,
    expected_preflight_calls: usize = 0,
    active_slot: usize = 0,

    fn index(address: usize) usize {
        std.debug.assert(address >= base and address < base + capacity * PAGE_SIZE);
        return (address - base) / PAGE_SIZE;
    }

    fn validate(self: *@This(), address: usize) UserMapError!void {
        self.preflight_calls += 1;
        const slot = index(address);
        if (self.foreign_slot == slot) return error.KernelMappingCollision;
        if (entryPresent(self.entries[slot])) return error.AlreadyMapped;
    }

    fn mapHuge(self: *@This(), address: usize, permissions: UserPermissions) UserMapError!bool {
        std.debug.assert(self.preflight_calls == self.expected_preflight_calls);
        self.huge_attempts += 1;
        if (!self.allow_huge or self.frame_budget < LARGE_2M_FRAME_COUNT) return false;
        const slot = index(address);
        const value = try ownedUserHugeLeaf(0x200000, permissions);
        for (self.entries[slot..][0..LARGE_2M_FRAME_COUNT]) |*entry| entry.* = value;
        self.frame_budget -= LARGE_2M_FRAME_COUNT;
        self.allocated_frames += LARGE_2M_FRAME_COUNT;
        self.huge_mappings += 1;
        return true;
    }

    fn mapSmall(self: *@This(), address: usize, permissions: UserPermissions) UserMapError!void {
        std.debug.assert(self.preflight_calls == self.expected_preflight_calls);
        return initializeOwnedUserPage(self, address, permissions, null);
    }

    fn leaf(self: *@This(), address: usize) UserMapError!*PageTableEntry {
        self.small_walks += 1;
        self.active_slot = index(address);
        if (self.foreign_slot == self.active_slot) return error.KernelMappingCollision;
        if (self.fail_leaf_slot == self.active_slot) return error.OutOfMemory;
        return &self.entries[self.active_slot];
    }

    fn allocate(self: *@This()) ?frame_allocator.PhysicalAddress {
        if (self.frame_budget == 0) return null;
        self.frame_budget -= 1;
        self.allocated_frames += 1;
        return self.allocated_frames * PAGE_SIZE;
    }

    fn bytes(self: *@This(), _: frame_allocator.PhysicalAddress) *[PAGE_SIZE]u8 {
        std.debug.assert(!entryPresent(self.entries[self.active_slot]));
        return &self.frame;
    }
} else struct {};

test "owned range mapping preflights each slot once before its independent small leaf checks" {
    var backend = OwnedRangeTestBackend{ .expected_preflight_calls = 3 };
    try mapOwnedUserRangeWith(&backend, OwnedRangeTestBackend.base, 3 * PAGE_SIZE, .{ .writable = false });
    try std.testing.expectEqual(@as(usize, 3), backend.preflight_calls);
    try std.testing.expectEqual(@as(usize, 3), backend.small_walks);
    try std.testing.expectEqual(@as(usize, 3), backend.allocated_frames);
    try std.testing.expectEqual(@as(usize, 0), backend.huge_attempts);
    for (backend.entries[0..3]) |entry| {
        try std.testing.expect(entryPresent(entry));
        try std.testing.expectEqual(PAGE_OWNER_USER_PRIVATE, entryOwner(entry));
        try std.testing.expect((entry & ENTRY_USER) != 0);
        try std.testing.expect((entry & ENTRY_WRITABLE) == 0);
        try std.testing.expect(!table64.isExecutable(entry));
    }
}

test "owned range preflight collisions leave earlier slots and frame allocation untouched" {
    const existing = tableEntry(0xA000, ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE | table64.NO_EXECUTE, PAGE_OWNER_USER_PRIVATE);
    var backend = OwnedRangeTestBackend{ .expected_preflight_calls = 3 };
    backend.entries[2] = existing;
    try std.testing.expectError(error.AlreadyMapped, mapOwnedUserRangeWith(&backend, OwnedRangeTestBackend.base, 3 * PAGE_SIZE, .{ .writable = true }));
    try std.testing.expectEqual(@as(usize, 3), backend.preflight_calls);
    try std.testing.expectEqual(@as(PageTableEntry, 0), backend.entries[0]);
    try std.testing.expectEqual(@as(PageTableEntry, 0), backend.entries[1]);
    try std.testing.expectEqual(existing, backend.entries[2]);
    try std.testing.expectEqual(@as(usize, 0), backend.small_walks);
    try std.testing.expectEqual(@as(usize, 0), backend.allocated_frames);
    try std.testing.expectEqual(@as(usize, 0), backend.huge_attempts);
    for (backend.frame) |byte| try std.testing.expectEqual(@as(u8, 0xA5), byte);

    backend = .{ .foreign_slot = 2, .expected_preflight_calls = 3 };
    try std.testing.expectError(error.KernelMappingCollision, mapOwnedUserRangeWith(&backend, OwnedRangeTestBackend.base, 3 * PAGE_SIZE, .{ .writable = true }));
    try std.testing.expectEqual(@as(usize, 3), backend.preflight_calls);
    try std.testing.expectEqual(@as(usize, 0), backend.small_walks);
    try std.testing.expectEqual(@as(usize, 0), backend.allocated_frames);
    for (backend.entries) |entry| try std.testing.expectEqual(@as(PageTableEntry, 0), entry);
}

test "owned range mapping preserves a small prefix huge middle and small tail" {
    var backend = OwnedRangeTestBackend{ .expected_preflight_calls = 1024 };
    try mapOwnedUserRangeWith(&backend, OwnedRangeTestBackend.base + PAGE_SIZE, 1024 * PAGE_SIZE, .{ .writable = true });
    try std.testing.expectEqual(@as(usize, 1024), backend.preflight_calls);
    try std.testing.expectEqual(@as(usize, 512), backend.small_walks);
    try std.testing.expectEqual(@as(usize, 1), backend.huge_attempts);
    try std.testing.expectEqual(@as(usize, 1), backend.huge_mappings);
    try std.testing.expectEqual(@as(usize, 1024), backend.allocated_frames);
    try std.testing.expectEqual(@as(PageTableEntry, 0), backend.entries[0]);
    try std.testing.expect(!table64.isLargePage(backend.entries[511]));
    try std.testing.expect(table64.isLargePage(backend.entries[512]));
    try std.testing.expect(!table64.isLargePage(backend.entries[1024]));
    for (backend.entries[1..]) |entry| try std.testing.expect(entryPresent(entry) and (entry & ENTRY_WRITABLE) != 0);
}

test "owned range mapping retains small-page fallback and partial progress under frame pressure" {
    var backend = OwnedRangeTestBackend{ .allow_huge = false, .expected_preflight_calls = 512 };
    try mapOwnedUserRangeWith(&backend, OwnedRangeTestBackend.base, @intCast(LARGE_2M_PAGE_SIZE), .{ .writable = true });
    try std.testing.expectEqual(@as(usize, 512), backend.preflight_calls);
    try std.testing.expectEqual(@as(usize, 512), backend.small_walks);
    try std.testing.expectEqual(@as(usize, 1), backend.huge_attempts);
    try std.testing.expectEqual(@as(usize, 0), backend.huge_mappings);
    try std.testing.expectEqual(@as(usize, 512), backend.allocated_frames);

    backend = .{ .frame_budget = 1, .expected_preflight_calls = 512 };
    try std.testing.expectError(error.OutOfMemory, mapOwnedUserRangeWith(&backend, OwnedRangeTestBackend.base, @intCast(LARGE_2M_PAGE_SIZE), .{ .writable = true }));
    try std.testing.expectEqual(@as(usize, 512), backend.preflight_calls);
    try std.testing.expectEqual(@as(usize, 2), backend.small_walks);
    try std.testing.expectEqual(@as(usize, 1), backend.huge_attempts);
    try std.testing.expectEqual(@as(usize, 0), backend.huge_mappings);
    try std.testing.expectEqual(@as(usize, 1), backend.allocated_frames);
    try std.testing.expect(entryPresent(backend.entries[0]));
    for (backend.entries[1..]) |entry| try std.testing.expectEqual(@as(PageTableEntry, 0), entry);

    backend = .{ .fail_leaf_slot = 1, .expected_preflight_calls = 2 };
    try std.testing.expectError(error.OutOfMemory, mapOwnedUserRangeWith(&backend, OwnedRangeTestBackend.base, 2 * PAGE_SIZE, .{ .writable = true }));
    try std.testing.expectEqual(@as(usize, 2), backend.preflight_calls);
    try std.testing.expectEqual(@as(usize, 2), backend.small_walks);
    try std.testing.expectEqual(@as(usize, 1), backend.allocated_frames);
    try std.testing.expect(entryPresent(backend.entries[0]));
    try std.testing.expectEqual(@as(PageTableEntry, 0), backend.entries[1]);
}

test "owned page initialization publishes complete zero or copied contents and preserves existing leaves" {
    const Model = struct {
        entry: PageTableEntry = 0,
        frame: [PAGE_SIZE]u8 = @splat(0xA5),
        allocations: usize = 0,
        fail_allocation: bool = false,
        foreign_table: bool = false,

        fn leaf(self: *@This(), _: usize) UserMapError!*PageTableEntry {
            if (self.foreign_table) return error.KernelMappingCollision;
            return &self.entry;
        }

        fn allocate(self: *@This()) ?frame_allocator.PhysicalAddress {
            if (self.fail_allocation) return null;
            self.allocations += 1;
            return 0xA000;
        }

        fn bytes(self: *@This(), _: frame_allocator.PhysicalAddress) *[PAGE_SIZE]u8 {
            std.debug.assert(!entryPresent(self.entry));
            return &self.frame;
        }
    };
    var model = Model{};
    var source: [PAGE_SIZE]u8 = undefined;
    for (&source, 0..) |*byte, index| byte.* = @truncate(index * 37);
    const permissions = UserPermissions{ .writable = false };
    for ([_]UserPermissions{ .{ .writable = false, .write_through = true }, .{ .writable = false, .cache_disabled = true } }) |invalid_cache| {
        try std.testing.expectError(error.InvalidRange, initializeOwnedUserPage(&model, 0x4000_0000, invalid_cache, &source));
        try std.testing.expectEqual(@as(usize, 0), model.allocations);
        try std.testing.expectEqual(@as(PageTableEntry, 0), model.entry);
        try std.testing.expectError(error.InvalidRange, ownedUserHugeLeaf(0x200000, invalid_cache));
        var empty_directory: PageDirectory = @splat(0);
        var empty_space = UserAddressSpace{ .directory = &empty_directory, .pcid = 1, .switch_cr3 = 0 };
        try std.testing.expectError(error.InvalidRange, mapBorrowedPhysicalUserRange(&empty_space, 0x4000_0000, 0x200000, PAGE_SIZE, invalid_cache));
        try std.testing.expectError(error.InvalidRange, mapOwnedUserRange(&empty_space, 0x4000_0000, PAGE_SIZE, invalid_cache));
        try std.testing.expectError(error.InvalidRange, mapOwnedUserPageFromPhysical(&empty_space, 0x4000_0000, 0x200000, invalid_cache));
        try std.testing.expectEqualSlices(u64, &@as(PageDirectory, @splat(0)), &empty_directory);
    }
    try initializeOwnedUserPage(&model, 0x4000_0000, permissions, &source);
    try std.testing.expectEqualSlices(u8, &source, &model.frame);
    try std.testing.expectEqual(@as(usize, 1), model.allocations);
    try std.testing.expectEqual(@as(usize, 0xA000), entryAddress(model.entry));
    try std.testing.expectEqual(PAGE_OWNER_USER_PRIVATE, entryOwner(model.entry));
    try std.testing.expect(entryPresent(model.entry));
    try std.testing.expect((model.entry & ENTRY_USER) != 0);
    try std.testing.expect((model.entry & ENTRY_WRITABLE) == 0);
    try std.testing.expect((model.entry & ENTRY_WRITE_THROUGH) == 0);
    try std.testing.expect((model.entry & ENTRY_CACHE_DISABLE) == 0);
    try std.testing.expect(!table64.isExecutable(model.entry));

    // A repeated fault must never overwrite the task's private changes.
    model.entry |= ENTRY_WRITABLE;
    const existing = model.entry;
    @memset(&model.frame, 0x42);
    try std.testing.expectError(error.AlreadyMapped, initializeOwnedUserPage(&model, 0x4000_0000, permissions, &source));
    try std.testing.expectEqual(existing, model.entry);
    try std.testing.expectEqual(@as(usize, 1), model.allocations);
    for (model.frame) |byte| try std.testing.expectEqual(@as(u8, 0x42), byte);

    model = .{ .fail_allocation = true };
    try std.testing.expectError(error.OutOfMemory, initializeOwnedUserPage(&model, 0x4000_0000, permissions, &source));
    try std.testing.expectEqual(@as(PageTableEntry, 0), model.entry);
    try std.testing.expectEqual(@as(usize, 0), model.allocations);
    for (model.frame) |byte| try std.testing.expectEqual(@as(u8, 0xA5), byte);

    model = .{ .foreign_table = true };
    try std.testing.expectError(error.KernelMappingCollision, initializeOwnedUserPage(&model, 0x4000_0000, permissions, &source));
    try std.testing.expectEqual(@as(PageTableEntry, 0), model.entry);
    try std.testing.expectEqual(@as(usize, 0), model.allocations);
    for (model.frame) |byte| try std.testing.expectEqual(@as(u8, 0xA5), byte);

    model = .{};
    try initializeOwnedUserPage(&model, 0x4000_0000, .{ .writable = true }, null);
    try std.testing.expectEqual(@as(usize, 1), model.allocations);
    try std.testing.expect((model.entry & ENTRY_WRITABLE) != 0);
    for (model.frame) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "owned physical page mapping rejects invalid source geometry before walking or allocating" {
    var space: UserAddressSpace = undefined;
    const permissions = UserPermissions{ .writable = false };
    for ([_]u64{ 1, MANAGED_PHYSICAL_BYTES - PAGE_SIZE + 1, MANAGED_PHYSICAL_BYTES, std.math.maxInt(u64) }) |source| {
        try std.testing.expectError(error.InvalidRange, mapOwnedUserPageFromPhysical(&space, 0x4000_0000, source, permissions));
    }
    try std.testing.expectError(error.InvalidRange, mapOwnedUserPageFromPhysical(&space, 0x4000_0001, 0x2000, permissions));
    try std.testing.expectError(error.InvalidRange, mapOwnedUserPageFromPhysical(&space, 0x0000_8000_0000_0000, 0x2000, permissions));
    try std.testing.expectError(error.WritableExecutable, mapOwnedUserPageFromPhysical(&space, 0x4000_0000, 0x2000, .{ .writable = true, .executable = true }));
}

test "child table release publication exposes only zeroed entries to a concurrent walker" {
    const Model = struct {
        const iterations = 256;
        const value = ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER | 0xA000;
        entry: PageTableEntry = 0,
        table: PageTable = undefined,
        failed: bool = false,

        fn observe(self: *@This()) void {
            for (0..iterations) |_| {
                while (@atomicLoad(PageTableEntry, &self.entry, .acquire) == 0) std.atomic.spinLoopHint();
                for (self.table) |leaf| {
                    if (leaf != 0) self.failed = true;
                }
                @atomicStore(PageTableEntry, &self.entry, 0, .release);
            }
        }
    };
    var model = Model{};
    const observer = try std.Thread.spawn(.{}, Model.observe, .{&model});
    for (0..Model.iterations) |_| {
        while (@atomicLoad(PageTableEntry, &model.entry, .acquire) != 0) std.atomic.spinLoopHint();
        @memset(&model.table, std.math.maxInt(PageTableEntry));
        publishZeroedTable(&model.entry, &model.table, Model.value);
    }
    observer.join();
    try std.testing.expect(!model.failed);
}

pub fn ownedUserPageIsExecutable(space: *const UserAddressSpace, virtual_address: usize) ?bool {
    const entry = lookupLeaf(space.directory, virtual_address) orelse return null;
    if (!entryPresent(entry.*) or entryOwner(entry.*) != PAGE_OWNER_USER_PRIVATE) return null;
    if ((entry.* & ENTRY_USER) == 0) return null;
    return table64.isExecutable(entry.*);
}

fn writablePrivateUserLeaf(entry: PageTableEntry) UserWriteError!PageTableEntry {
    if (!entryPresent(entry) or entryOwner(entry) != PAGE_OWNER_USER_PRIVATE or
        (entry & ENTRY_USER) == 0 or table64.isExecutable(entry) or
        entry & (ENTRY_LARGE_PAGE | ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE | ENTRY_GLOBAL) != 0 or
        entry & ~(@as(u64, 0x000F_FFFF_FFFF_FFFF) | table64.NO_EXECUTE | table64.PROTECTION_KEY_MASK) != 0 or
        entryAddress(entry) > MANAGED_PHYSICAL_BYTES - PAGE_SIZE)
        return error.PageNotOwned;
    return entry | ENTRY_WRITABLE;
}

fn publishOwnedUserWriteWith(comptime tables: type, directory: *PageDirectory, virtual_start: usize) UserWriteError!bool {
    if (pageOffset(virtual_start) != 0 or virtual_start >= 0x0000_8000_0000_0000) return error.InvalidRange;
    var current = directory;
    for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }) |shift| {
        const entry = current[tableIndex(virtual_start, shift)];
        if (!entryPresent(entry) or entryOwner(entry) != TABLE_OWNER_USER_PRIVATE or
            entry & (ENTRY_USER | ENTRY_WRITABLE) != ENTRY_USER | ENTRY_WRITABLE or
            entry & (ENTRY_LARGE_PAGE | ENTRY_WRITE_THROUGH | ENTRY_CACHE_DISABLE | ENTRY_GLOBAL | table64.PROTECTION_KEY_MASK) != 0 or
            entry & ~(@as(u64, 0x000F_FFFF_FFFF_FFFF) | table64.NO_EXECUTE) != 0 or
            entryAddress(entry) == 0 or entryAddress(entry) >= MANAGED_PHYSICAL_BYTES)
            return error.PageNotOwned;
        // The owner tag alone cannot authorize a sparse alias or retired frame.
        current = tables.table(entry) orelse return error.PageNotOwned;
    }
    const entry = &current[tableIndex(virtual_start, PAGE_TABLE_SHIFT)];
    const original = entry.*;
    const promoted = try writablePrivateUserLeaf(original);
    if (!tables.allocated(entryAddress(original))) return error.PageNotOwned;
    if (promoted == original) return false;
    // Hardware may set A/D while the single software owner prepares a page.
    // OR preserves those concurrent updates as well as the validated key/base.
    _ = @atomicRmw(PageTableEntry, entry, .Or, ENTRY_WRITABLE, .release);
    return true;
}

const UserWriteInvalidation = struct {
    fn invalidate(_: @This(), space: *const UserAddressSpace) void {
        invalidateUserContext(space);
    }
};

fn promoteOwnedUserWriteWith(comptime tables: type, backend: anytype, space: *const UserAddressSpace, virtual_start: usize) UserWriteError!bool {
    const changed = try publishOwnedUserWriteWith(tables, space.directory, virtual_start);
    if (changed) backend.invalidate(space);
    return changed;
}

// A hardware fault has one permission change and must retire it immediately.
pub fn promoteOwnedUserPageForWrite(space: *const UserAddressSpace, virtual_start: usize) UserWriteError!bool {
    return promoteOwnedUserWriteWith(SharedUserTables, UserWriteInvalidation{}, space, virtual_start);
}

// Synchronous supervisor preparation owns one root, with no callback, yield or
// IRQ enable until finish. It publishes only existing private 4 KiB data leaves;
// absent-to-present materialization does not add a stale translation to retire.
pub const UserWriteBatch = struct {
    space: *const UserAddressSpace,
    changed: bool = false,

    pub fn initInto(space: *const UserAddressSpace, out: *UserWriteBatch) bool {
        if (comptime builtin.target.os.tag != .freestanding) return false;
        return initIntoWith(space, out, cpu_identity.currentIndex(), x86.interruptsEnabled());
    }

    fn initIntoWith(space: *const UserAddressSpace, out: *UserWriteBatch, cpu: u8, interrupts_enabled: bool) bool {
        if (cpu != 0 or interrupts_enabled) return false;
        out.* = .{ .space = space };
        return true;
    }

    pub fn promote(self: *UserWriteBatch, virtual_start: usize) UserWriteError!bool {
        return self.promoteWith(SharedUserTables, virtual_start);
    }

    fn promoteWith(self: *UserWriteBatch, comptime tables: type, virtual_start: usize) UserWriteError!bool {
        const changed = try publishOwnedUserWriteWith(tables, self.space.directory, virtual_start);
        self.changed = self.changed or changed;
        return changed;
    }

    pub fn finish(self: *UserWriteBatch) void {
        self.finishWith(UserWriteInvalidation{});
    }

    fn finishWith(self: *UserWriteBatch, backend: anytype) void {
        if (!self.changed) return;
        backend.invalidate(self.space);
        self.changed = false;
    }
};

pub fn writeOwnedUserRange(
    space: *const UserAddressSpace,
    virtual_start: usize,
    source: []const u8,
) UserWriteError!void {
    if (source.len == 0) return;
    _ = std.math.add(usize, virtual_start, source.len) catch return error.AddressOverflow;

    var copied: usize = 0;
    while (copied < source.len) {
        const virtual_address = virtual_start + copied;
        const entry = lookupLeaf(space.directory, virtual_address) orelse return error.PageNotOwned;
        if (!entryPresent(entry.*) or entryOwner(entry.*) != PAGE_OWNER_USER_PRIVATE) {
            return error.PageNotOwned;
        }

        const leaf_size: usize = if (table64.isLargePage(entry.*)) @intCast(LARGE_2M_PAGE_SIZE) else PAGE_SIZE;
        const offset_in_leaf = virtual_address & (leaf_size - 1);
        const copy_len = @min(source.len - copied, leaf_size - offset_in_leaf);
        const destination = bytesAtPhysical(@intCast(entryAddress(entry.*))) + offset_in_leaf;
        @memcpy(destination[0..copy_len], source[copied..][0..copy_len]);
        copied += copy_len;
    }
}

pub fn readOwnedUserRange(
    space: *const UserAddressSpace,
    virtual_start: usize,
    destination: []u8,
) UserWriteError!void {
    if (destination.len == 0) return;
    _ = std.math.add(usize, virtual_start, destination.len) catch return error.AddressOverflow;

    var copied: usize = 0;
    while (copied < destination.len) {
        const virtual_address = virtual_start + copied;
        const entry = lookupLeaf(space.directory, virtual_address) orelse return error.PageNotOwned;
        if (!entryPresent(entry.*) or entryOwner(entry.*) != PAGE_OWNER_USER_PRIVATE) {
            return error.PageNotOwned;
        }

        const leaf_size: usize = if (table64.isLargePage(entry.*)) @intCast(LARGE_2M_PAGE_SIZE) else PAGE_SIZE;
        const offset_in_leaf = virtual_address & (leaf_size - 1);
        const copy_len = @min(destination.len - copied, leaf_size - offset_in_leaf);
        const source = bytesAtPhysical(@intCast(entryAddress(entry.*))) + offset_in_leaf;
        @memcpy(destination[copied..][0..copy_len], source[0..copy_len]);
        copied += copy_len;
    }
}

const UserHierarchyRetirement = struct {
    space: *const UserAddressSpace,

    fn table(_: @This(), entry: PageTableEntry) *PageTable {
        return tableFromEntry(entry);
    }

    fn invalidate(self: @This()) void {
        invalidateUserContext(self.space);
    }

    fn release(_: @This(), physical: frame_allocator.PhysicalAddress, count: u32) void {
        releasePhysicalFramesLocked(physical, count) catch
            haltPagingFailure(.corrupt_retired_user_hierarchy_accounting);
    }
};

fn retireOwnedHierarchy(backend: anytype, pml4: *PageDirectory, root_physical: frame_allocator.PhysicalAddress) void {
    // Private root links become unreachable before flushing. Their retained
    // addresses and owner tags allow reclamation without a second root copy.
    for (pml4) |*entry| {
        if (entryPresent(entry.*) and entryOwner(entry.*) == TABLE_OWNER_USER_PRIVATE)
            @atomicStore(PageTableEntry, entry, entry.* & ~ENTRY_PRESENT, .release);
    }
    backend.invalidate();
    releaseDetachedHierarchy(backend, pml4);
    backend.release(root_physical, 1);
}

fn releaseDetachedHierarchy(backend: anytype, pml4: *PageDirectory) void {
    for (pml4) |*pml4_entry| {
        if (entryOwner(pml4_entry.*) != TABLE_OWNER_USER_PRIVATE) continue;
        const pdpt_phys: frame_allocator.PhysicalAddress = @intCast(entryAddress(pml4_entry.*));
        const pdpt = backend.table(pml4_entry.*);
        for (pdpt) |*pdpt_entry| {
            if (!entryPresent(pdpt_entry.*) or entryOwner(pdpt_entry.*) != TABLE_OWNER_USER_PRIVATE) continue;
            const page_directory_phys: frame_allocator.PhysicalAddress = @intCast(entryAddress(pdpt_entry.*));
            const page_directory = backend.table(pdpt_entry.*);
            for (page_directory) |*directory_entry| {
                if (!entryPresent(directory_entry.*) or
                    (entryOwner(directory_entry.*) != TABLE_OWNER_USER_PRIVATE and
                        entryOwner(directory_entry.*) != PAGE_OWNER_USER_PRIVATE)) continue;
                if (table64.isLargePage(directory_entry.*)) {
                    if (entryOwner(directory_entry.*) == PAGE_OWNER_USER_PRIVATE) {
                        backend.release(@intCast(entryAddress(directory_entry.*)), LARGE_2M_FRAME_COUNT);
                    }
                    directory_entry.* = 0;
                    continue;
                }
                const page_table_phys: frame_allocator.PhysicalAddress = @intCast(entryAddress(directory_entry.*));
                const page_table = backend.table(directory_entry.*);
                for (page_table) |*page_entry| {
                    if (entryPresent(page_entry.*) and entryOwner(page_entry.*) == PAGE_OWNER_USER_PRIVATE) {
                        backend.release(@intCast(entryAddress(page_entry.*)), 1);
                    }
                    page_entry.* = 0;
                }
                backend.release(page_table_phys, 1);
                directory_entry.* = 0;
            }
            backend.release(page_directory_phys, 1);
            pdpt_entry.* = 0;
        }
        backend.release(pdpt_phys, 1);
        pml4_entry.* = 0;
    }
}

/// Callers must quiesce every user of this address space first. The BSP runtime
/// owner enforces that today; remote invalidation does not stop running tasks.
pub fn userAddressSpaceQuiescent(space: *const UserAddressSpace) bool {
    if (space.directory == getCurrentPageDirectory() or current_roots.activeOnAnyCpu(space.directory)) return false;
    // Include actual hardware residency before callers retire any mapping
    // metadata. The cached root scan alone cannot admit a stale current CR3.
    if (builtin.target.os.tag == .freestanding and
        x86.readCr3() & x86.CR3_ADDRESS_MASK == space.switch_cr3 & x86.CR3_ADDRESS_MASK) return false;
    return true;
}

pub fn destroyUserAddressSpace(space: *UserAddressSpace) UserAddressSpaceDestroyError!void {
    // This is a checked preflight, not a concurrent dispatch or hotplug
    // protocol. The single runtime writer must still quiesce every root user.
    if (!userAddressSpaceQuiescent(space)) return error.AddressSpaceActive;

    acquireFrameLock();
    retireOwnedHierarchy(UserHierarchyRetirement{ .space = space }, space.directory, tablePhysicalAddress(space.directory));
    releaseFrameLock();
    releaseRetiredProcessContext(space.pcid);
    space.* = undefined;
}

test "address-space retirement detaches every private root before reclaiming data tables and identifiers" {
    const Allocator = frame_allocator.Fixed(4 * 1024 * 1024, PAGE_SIZE);
    const Model = struct {
        root: PageDirectory = @splat(0),
        tables: [4]PageTable = @splat(@splat(0)),
        table_run: FrameRun,
        small: FrameRun,
        huge: FrameRun,
        borrowed: FrameRun,
        frames: *Allocator,
        contexts: *pcid_allocator.Allocator,
        identifier: u16,
        invalidations: usize = 0,
        release_count: usize = 0,
        released_frames: u32 = 0,
        acknowledged: bool = false,
        valid: bool = true,

        fn table(self: *@This(), entry: PageTableEntry) *PageTable {
            const index = (entryAddress(entry) - self.table_run.base) / PAGE_SIZE - 1;
            return &self.tables[@intCast(index)];
        }

        fn invalidate(self: *@This()) void {
            for (&self.root) |*entry| {
                const value = @atomicLoad(PageTableEntry, entry, .acquire);
                if (entryOwner(value) == TABLE_OWNER_USER_PRIVATE and entryPresent(value)) self.valid = false;
            }
            if (entryAddress(self.root[0]) != self.table_run.base + PAGE_SIZE or
                entryAddress(self.root[1]) != self.table_run.base + 4 * PAGE_SIZE or
                self.release_count != 0 or !self.contexts.isAllocated(self.identifier)) self.valid = false;
            for (0..self.table_run.count) |index| {
                if (!self.frames.isAllocated(self.table_run.base + index * PAGE_SIZE)) self.valid = false;
            }
            if (!self.frames.isAllocated(self.small.base) or !self.frames.isAllocated(self.borrowed.base)) self.valid = false;
            for (0..self.huge.count) |index| {
                if (!self.frames.isAllocated(self.huge.base + index * PAGE_SIZE)) self.valid = false;
            }
            self.invalidations += 1;
            self.acknowledged = true;
        }

        fn release(self: *@This(), physical: frame_allocator.PhysicalAddress, count: u32) void {
            if (!self.acknowledged or self.invalidations != 1 or !self.contexts.isAllocated(self.identifier))
                self.valid = false;
            // The root itself is the last frame returned, after all descendants.
            if (physical == self.table_run.base and self.released_frames != self.table_run.count - 1 + self.small.count + self.huge.count)
                self.valid = false;
            self.frames.release(.{ .base = physical, .count = count }) catch {
                self.valid = false;
                return;
            };
            self.release_count += 1;
            self.released_frames += count;
        }
    };
    var storage: Allocator.Storage = undefined;
    var frames = Allocator.init(&storage);
    try frames.reserve(.{ .base = 0, .count = 1 });
    const table_run = frames.allocate(5).?;
    const small = frames.allocate(1).?;
    const borrowed = frames.allocate(1).?;
    const huge = frames.allocateAlignedBetween(LARGE_2M_FRAME_COUNT, LARGE_2M_FRAME_COUNT, 0, 4 * 1024 * 1024).?;
    var contexts = pcid_allocator.Allocator.init();
    const identifier = contexts.allocate().?;
    var model = Model{
        .table_run = table_run,
        .small = small,
        .huge = huge,
        .borrowed = borrowed,
        .frames = &frames,
        .contexts = &contexts,
        .identifier = identifier,
    };
    const table_flags = ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER;
    const leaf_flags = table_flags | table64.NO_EXECUTE;
    model.root[0] = tableEntry(@intCast(table_run.base + PAGE_SIZE), table_flags, TABLE_OWNER_USER_PRIVATE);
    model.root[1] = tableEntry(@intCast(table_run.base + 4 * PAGE_SIZE), table_flags, TABLE_OWNER_USER_PRIVATE);
    model.root[256] = tableEntry(@intCast(borrowed.base), ENTRY_PRESENT | ENTRY_WRITABLE, TABLE_OWNER_INHERITED);
    const inherited = model.root[256];
    model.tables[0][0] = tableEntry(@intCast(table_run.base + 2 * PAGE_SIZE), table_flags, TABLE_OWNER_USER_PRIVATE);
    model.tables[1][0] = tableEntry(@intCast(table_run.base + 3 * PAGE_SIZE), table_flags, TABLE_OWNER_USER_PRIVATE);
    model.tables[1][1] = tableEntry(@intCast(huge.base), leaf_flags | ENTRY_LARGE_PAGE, PAGE_OWNER_USER_PRIVATE);
    model.tables[2][0] = tableEntry(@intCast(small.base), leaf_flags, PAGE_OWNER_USER_PRIVATE);
    model.tables[2][1] = tableEntry(@intCast(borrowed.base), leaf_flags, PAGE_OWNER_BORROWED);

    retireOwnedHierarchy(&model, &model.root, table_run.base);
    try std.testing.expect(model.valid and model.acknowledged);
    try std.testing.expectEqual(@as(usize, 1), model.invalidations);
    try std.testing.expectEqual(@as(usize, 7), model.release_count);
    try std.testing.expectEqual(table_run.count + small.count + huge.count, model.released_frames);
    try std.testing.expectEqual(@as(u32, 1), frames.stats().allocated);
    try std.testing.expect(frames.isAllocated(borrowed.base));
    try std.testing.expectEqual(@as(PageTableEntry, 0), model.root[0]);
    try std.testing.expectEqual(@as(PageTableEntry, 0), model.root[1]);
    try std.testing.expectEqual(inherited, model.root[256]);
    try std.testing.expect(contexts.isAllocated(identifier));
    try contexts.release(identifier);
    try std.testing.expectEqual(identifier, contexts.allocate().?);
    const reused_tables = frames.allocate(table_run.count).?;
    try std.testing.expectEqualDeep(table_run, reused_tables);
}

pub fn switchToUserAddressSpace(space: *const UserAddressSpace) void {
    switchAddressSpace(space.directory, space.switch_cr3);
}

pub fn activateUserDomain(space: *const UserAddressSpace, protection_key: u4) void {
    _ = protection_key;
    switchToUserAddressSpace(space);
}

pub inline fn switchToKernelAddressSpace() void {
    switchAddressSpace(kernelPageDirectory(), kernel_switch_cr3);
}

// init has admitted the complete immutable handoff before opening any frames.
// The shared builder still preflights writable WB arena backing and capacity.
fn initializeKernelHierarchy(arenas: efi_handoff.paging_info.Info, memory_map: handoff.MemoryMap, cache: cache_policy.ValidatedMtrrView) usize {
    var entries: [256]efi_handoff.MmapEntry = undefined;
    var entry_count: usize = 0;
    var iterator = memory_map.iterator();
    while (iterator.next() catch haltPagingFailure(.invalid_native_memory_map)) |entry| {
        if (entry.length == 0) continue;
        if (entry_count == entries.len) haltPagingFailure(.native_memory_map_capacity_exceeded);
        entries[entry_count] = .{ .base = entry.base, .length = entry.length, .kind = entry.kind, .firmware_type = entry.firmware_type, .attributes = entry.attributes };
        entry_count += 1;
    }
    efi_paging.sortEntries(entries[0..entry_count]);
    var direct: [256]sparse.Region = undefined;
    const direct_count = efi_paging.ramRegions(entries[0..entry_count], &direct, arenas.framebufferSpan() catch
        haltPagingFailure(.invalid_framebuffer_ownership_extent)) catch
        haltPagingFailure(.invalid_ram_direct_map_authority);
    const image = kernelImageExtents();
    const image_regions = [_]sparse.Region{
        .{ .start = image.text_start, .end = image.text_end, .permissions = .{ .writable = false, .executable = true } },
        .{ .start = image.text_end, .end = image.immutable_end, .permissions = .{ .writable = false } },
        .{ .start = image.immutable_end, .end = image.image_end, .permissions = .{ .force_4k = true } },
    };
    var overlays = [_]sparse.Region{
        .{ .start = image.text_start, .end = image.immutable_end, .permissions = .{ .writable = false } },
        .{ .start = memory.heapPhysicalStartAddress(), .end = memory.heapPhysicalStartAddress() + memory.HEAP_SIZE, .permissions = .{ .force_4k = true } },
    };
    efi_paging.sortRegions(&overlays);
    const alias = directMapAddress(arenas.final_base) orelse haltPagingFailure(.final_paging_arena_outside_direct_map_aperture);
    const tables: [*]align(PAGE_SIZE) PageTable = @ptrFromInt(alias);
    var result: sparse.Result = undefined;
    sparse.build(tables[0..arenas.final_pages], arenas.final_base, null, .{
        .cache = cache,
        .image = &image_regions,
        .direct = direct[0..direct_count],
        .direct_overlays = &overlays,
        .global = true,
    }, &result) catch haltPagingFailure(.sparse_kernel_hierarchy_admission_failed);
    bootstrap_root = &tables[0];
    return result.used_pages;
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
        haltPagingFailure(.corrupt_high_memory_probe_accounting);

    const direct_alias = directMapAddress(run.base) orelse
        haltPagingFailure(.high_memory_probe_outside_direct_map_aperture);
    const permissions = currentPagePermissions(direct_alias) orelse
        haltPagingFailure(.high_memory_direct_map_leaf_missing);
    if (!permissions.writable or permissions.executable or permissions.user) {
        haltPagingFailure(.high_memory_direct_map_permissions_are_invalid);
    }
    const probe: *volatile u8 = @ptrFromInt(direct_alias);
    const previous = probe.*;
    const pattern = previous ^ 0xA5;
    probe.* = pattern;
    if (probe.* != pattern) haltPagingFailure(.high_memory_direct_map_probe_failed);
    probe.* = previous;
    return true;
}

pub fn init() void {
    const restore_interrupts = x86.interruptsEnabled();
    x86.cli();
    defer if (restore_interrupts) x86.sti();
    if (bootstrap_root != null) haltPagingFailure(.invalid_native_boot_memory_ownership);
    early_console.print("Initializing four-level paging...\n");

    const boot_info = handoff.capturedInfo() orelse
        haltPagingFailure(.missing_multiboot_memory_map_handoff);
    const boot_info_address = handoff.capturedInfoAddress() orelse
        haltPagingFailure(.invalid_multiboot_information_extent);
    const memory_map = handoff.capturedMemoryMap(boot_info) orelse
        haltPagingFailure(.missing_multiboot_memory_map);
    const cache = cache_policy.admittedMtrrView() catch haltPagingFailure(.missing_admitted_cache_policy);
    firmware_memory_map.validateBootOwnedRanges(memory_map, boot_info_address, boot_info, memory.kernelPhysicalStartAddress(), memory.kernelPhysicalEndAddress(), cache) catch
        haltPagingFailure(.invalid_native_boot_memory_ownership);
    @import("../platform/smbios.zig").captureTargetSku(boot_info.efi64_system_table_addr);
    const frame_storage_memory = memory.claimEarly(
        PhysicalFrameAllocator.storage_bytes,
        @alignOf(PhysicalFrameAllocator.Storage),
    ) orelse haltPagingFailure(.insufficient_early_heap_for_physical_frame_state);
    const frame_storage: *PhysicalFrameAllocator.Storage = @ptrCast(@alignCast(frame_storage_memory));
    physical_frames = PhysicalFrameAllocator.bindStorage(frame_storage);
    firmware_memory_map.initializeAllocator(MANAGED_PHYSICAL_BYTES, PAGE_SIZE, &physical_frames, memory_map, cache) catch
        haltPagingFailure(.invalid_multiboot_memory_map);
    high_memory_zone_has_free_frames = false;
    low_identity_frame_cursor = .{};
    firmware_memory_map.reserveLiveHandoffRanges(
        MANAGED_PHYSICAL_BYTES,
        PAGE_SIZE,
        &physical_frames,
        boot_info_address,
        boot_info,
    ) catch haltPagingFailure(.invalid_live_multiboot_handoff_extent);

    reserved_sipi_page = selectSipiPage(&physical_frames);

    const final_used_pages = initializeKernelHierarchy(boot_info.boot_paging.?, memory_map, cache);

    firmware_memory_map.reserveKernelRanges(
        MANAGED_PHYSICAL_BYTES,
        PAGE_SIZE,
        &physical_frames,
        memory.kernelPhysicalStartAddress(),
        memory.kernelPhysicalEndAddress(),
        memory.heapPhysicalStartAddress(),
        memory.HEAP_SIZE,
    ) catch haltPagingFailure(.invalid_kernel_or_efi_heap_reservation);
    const boot_image = boot_info.boot_image.?;
    kernel_mapping_authority = .{
        .memory_map = memory_map,
        .info_address = boot_info_address,
        .info = boot_info,
        .image = .{ .start = memory.kernelPhysicalStartAddress(), .end = memory.kernelPhysicalEndAddress() },
        .heap = .{ .start = boot_image.heap_base, .end = boot_image.heap_base + memory.HEAP_SIZE },
        .managed_bytes = MANAGED_PHYSICAL_BYTES,
    };
    enableWriteProtect();
    process_context_identifiers_enabled = x86.processContextIdentifiersEnabled();
    const kernel_pml4_physical = @as(usize, @intCast(tablePhysicalAddress(kernelPageDirectory())));
    // The EFI transition retained firmware code/stack mappings, which may
    // have filled global TLB entries. Retire those aliases with the old root.
    const previous_cr4 = x86.readCr4();
    if (previous_cr4 & x86.CR4_PGE != 0) x86.writeCr4(previous_cr4 & ~x86.CR4_PGE);
    x86.writeCr3(kernel_pml4_physical);
    if (previous_cr4 & x86.CR4_PGE != 0) x86.writeCr4(previous_cr4);
    kernel_switch_cr3 = addressSpaceCr3(kernel_pml4_physical, pcid_allocator.KERNEL_IDENTIFIER);
    initializeCurrentKernelRoot();
    // No AP has started and interrupts remain disabled. The final root and
    // global translations are verified before opening either obsolete range.
    firmware_memory_map.reclaimBootPagingArenas(
        MANAGED_PHYSICAL_BYTES,
        PAGE_SIZE,
        &physical_frames,
        &boot_arena_retirement,
        memory_map,
        boot_info_address,
        boot_info,
        memory.kernelPhysicalStartAddress(),
        memory.kernelPhysicalEndAddress(),
        cache,
        x86.readCr3() & x86.CR3_ADDRESS_MASK,
        @intCast(final_used_pages),
    ) catch haltPagingFailure(.invalid_native_boot_memory_ownership);
    physical_frames.sealReservations() catch
        haltPagingFailure(.physical_memory_reservation_table_overflow);
    if (physical_frames.stats().free == 0) {
        haltPagingFailure(.no_usable_physical_frames_remain_after_kernel_reservation);
    }
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

const RootTrackingError = error{
    InvalidCpu,
    InvalidRoot,
    Uninitialized,
    AlreadyInitialized,
    HardwareMismatch,
};

const CurrentRootSlot = struct {
    directory: usize align(128) = 0,
};

const CurrentRootTracker = struct {
    slots: [cpu_identity.MAX_CPUS]CurrentRootSlot = @splat(.{}),

    fn slot(self: *@This(), index: u8) RootTrackingError!*CurrentRootSlot {
        if (index >= self.slots.len) return error.InvalidCpu;
        return &self.slots[index];
    }

    inline fn get(self: *@This(), index: u8) RootTrackingError!*PageDirectory {
        const selected = try self.slot(index);
        const directory = @atomicLoad(usize, &selected.directory, .acquire);
        if (directory == 0) return error.Uninitialized;
        return @ptrFromInt(directory);
    }

    fn initialize(self: *@This(), index: u8, directory: *PageDirectory, switch_cr3: usize, actual_cr3: usize) RootTrackingError!void {
        const selected = try self.slot(index);
        if (@atomicLoad(usize, &selected.directory, .acquire) != 0) return error.AlreadyInitialized;
        try validateTrackedRoot(directory, switch_cr3);
        if (!cr3ReadbackMatchesSwitch(actual_cr3, switch_cr3)) return error.HardwareMismatch;
        @atomicStore(usize, &selected.directory, @intFromPtr(directory), .release);
    }

    fn switchWith(self: *@This(), index: u8, directory: *PageDirectory, switch_cr3: usize, backend: anytype) RootTrackingError!void {
        const previous = try self.get(index);
        try validateTrackedRoot(directory, switch_cr3);
        if (directory == previous and cr3ReadbackMatchesSwitch(backend.read(), switch_cr3)) return;
        backend.write(switch_cr3);
        if (!cr3ReadbackMatchesSwitch(backend.read(), switch_cr3)) return error.HardwareMismatch;
        @atomicStore(usize, &(try self.slot(index)).directory, @intFromPtr(directory), .release);
    }

    fn activeOnAnyCpu(self: *@This(), directory: *const PageDirectory) bool {
        for (&self.slots) |*selected| {
            if (@atomicLoad(usize, &selected.directory, .acquire) == @intFromPtr(directory)) return true;
        }
        return false;
    }
};

var current_roots: CurrentRootTracker = .{};
var kernel_switch_cr3: usize = 0;

inline fn trackedCurrentDirectory() RootTrackingError!*PageDirectory {
    return current_roots.get(cpu_identity.currentIndex());
}

pub inline fn getCurrentPageDirectory() *PageDirectory {
    return trackedCurrentDirectory() catch haltPagingFailure(.current_cpu_has_no_verified_paging_root);
}

// The BSP calls this after installing the final hierarchy. Every AP must call
// it after publishing RDPID identity and before publishing online admission.
// It validates the inherited physical kernel CR3; no absent slot gets a root
// merely because another CPU initialized the shared bootstrap hierarchy.
pub fn initializeCurrentKernelRoot() void {
    if (kernel_switch_cr3 == 0) haltPagingFailure(.kernel_paging_root_not_initialized);
    const restore_interrupts = x86.interruptsEnabled();
    x86.cli();
    defer if (restore_interrupts) x86.sti();
    current_roots.initialize(cpu_identity.currentIndex(), kernelPageDirectory(), kernel_switch_cr3, x86.readCr3()) catch
        haltPagingFailure(.current_cpu_failed_kernel_cr3_admission);
}

fn validateTrackedRoot(directory: *const PageDirectory, switch_cr3: usize) RootTrackingError!void {
    const physical = virtual_layout.directMappedPhysicalAddress(@intFromPtr(directory), MANAGED_PHYSICAL_BYTES) orelse
        return error.InvalidRoot;
    if (physical == 0 or physical % PAGE_SIZE != 0 or
        (switch_cr3 & ~(x86.CR3_ADDRESS_MASK | x86.CR3_PCID_MASK | x86.CR3_NO_FLUSH)) != 0 or
        (switch_cr3 & x86.CR3_ADDRESS_MASK) != physical) return error.InvalidRoot;
}

fn addressSpaceCr3(directory_physical: frame_allocator.PhysicalAddress, pcid: pcid_allocator.Identifier) usize {
    const cr3_base = std.math.cast(usize, directory_physical) orelse
        haltPagingFailure(.address_space_root_exceeds_machine_address_width);
    if (!process_context_identifiers_enabled) return cr3_base;
    return x86.pcidCr3Value(cr3_base, pcid, true) orelse
        haltPagingFailure(.invalid_address_space_cr3_value);
}

fn switchAddressSpace(directory: *PageDirectory, switch_cr3: usize) void {
    // An IRQ that switches roots between MOV CR3 and publication would leave
    // this CPU's hardware and software state inconsistent. Preserve caller IF.
    const restore_interrupts = x86.interruptsEnabled();
    x86.cli();
    defer if (restore_interrupts) x86.sti();
    switchTrackedCurrentRootWith(directory, switch_cr3, HardwareRootSwitch{}) catch
        haltPagingFailure(.address_space_switch_failed_cr3_readback);
}

const HardwareRootSwitch = struct {
    fn read(_: @This()) usize {
        return x86.readCr3();
    }

    fn write(_: @This(), value: usize) void {
        if (!x86.processContextIdentifiersEnabled() and (value & ~x86.CR3_ADDRESS_MASK) != 0)
            haltPagingFailure(.pcid_switch_requires_current_cpu_admission);
        x86.writeCr3(value);
    }
};

fn switchTrackedCurrentRootWith(directory: *PageDirectory, switch_cr3: usize, backend: anytype) RootTrackingError!void {
    return current_roots.switchWith(cpu_identity.currentIndex(), directory, switch_cr3, backend);
}

inline fn cr3ReadbackMatchesSwitch(current_cr3: usize, switch_cr3: usize) bool {
    // NO_FLUSH controls MOV to CR3; hardware never retains it in CR3. Keep the
    // root and PCID comparison even when this CPU's cached directory matches.
    return current_cr3 == (switch_cr3 & ~x86.CR3_NO_FLUSH);
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
    if (PRECISE_IMAGE_BYTES != 64 * 1024 * 1024) {
        @compileError("the precise image region must cover the first 64 MiB");
    }
    if (PhysicalFrameAllocator.storage_bytes + (2 * PAGE_SIZE) >= memory.HEAP_SIZE - (8 * 1024 * 1024)) {
        @compileError("early frame state leaves no kernel heap payload");
    }
    if (MANAGED_PHYSICAL_BYTES > virtual_layout.PHYSICAL_WINDOW_CAPACITY_BYTES) {
        @compileError("the managed physical aperture exceeds the direct-map window");
    }
    if (@alignOf(CurrentRootSlot) != 128 or @sizeOf(CurrentRootSlot) != 128) {
        @compileError("per-CPU current roots must occupy independent cache lines");
    }
    if (tableIndex(virtual_layout.physical_memory.base, PML4_SHIFT) == 0 or
        tableIndex(virtual_layout.physical_memory.base, PDPT_SHIFT) != 0)
    {
        @compileError("the direct-map window must begin at an isolated PML4 slot");
    }
}

test "CR3 readback ignores the transient switch control and preserves root and PCID identity" {
    const root_address: usize = 0x0000_0000_1234_5000;
    const current_cr3 = x86.pcidCr3Value(root_address, 7, false).?;
    const preserving_switch = x86.pcidCr3Value(root_address, 7, true).?;
    try std.testing.expect(current_cr3 != preserving_switch);
    try std.testing.expect(cr3ReadbackMatchesSwitch(current_cr3, preserving_switch));
    try std.testing.expect(cr3ReadbackMatchesSwitch(current_cr3, current_cr3));
    try std.testing.expect(!cr3ReadbackMatchesSwitch(
        x86.pcidCr3Value(root_address + PAGE_SIZE, 7, false).?,
        preserving_switch,
    ));
    try std.testing.expect(!cr3ReadbackMatchesSwitch(
        x86.pcidCr3Value(root_address, 8, false).?,
        preserving_switch,
    ));
    try std.testing.expect(cr3ReadbackMatchesSwitch(root_address, root_address));
}

test "current root admission rejects uninitialized mismatched and repeated CPU bindings" {
    var tracker: CurrentRootTracker = .{};
    const kernel: *PageDirectory = @ptrFromInt(virtual_layout.physical_memory.base + PAGE_SIZE);
    const expected = x86.pcidCr3Value(PAGE_SIZE, 0, true).?;
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2);
        try std.testing.expectError(error.Uninitialized, tracker.get(index));
        try std.testing.expectError(error.HardwareMismatch, tracker.initialize(index, kernel, expected, PAGE_SIZE | 1));
        try std.testing.expectError(error.Uninitialized, tracker.get(index));
        try tracker.initialize(index, kernel, expected, PAGE_SIZE);
        try std.testing.expectEqual(kernel, try tracker.get(index));
        try std.testing.expectError(error.AlreadyInitialized, tracker.initialize(index, kernel, expected, PAGE_SIZE));
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(&tracker.slots[index]) % 128);
        if (index != 0) try std.testing.expectEqual(@as(usize, 128), @intFromPtr(&tracker.slots[index]) - @intFromPtr(&tracker.slots[index - 1]));
    }
    try std.testing.expectError(error.InvalidCpu, tracker.get(cpu_identity.MAX_CPUS));
    try std.testing.expectError(error.InvalidCpu, tracker.initialize(cpu_identity.MAX_CPUS, kernel, expected, PAGE_SIZE));
    var empty: CurrentRootTracker = .{};
    try std.testing.expectError(error.InvalidRoot, empty.initialize(0, kernel, 2 * PAGE_SIZE, 2 * PAGE_SIZE));
    try std.testing.expectError(error.InvalidRoot, empty.initialize(0, @ptrFromInt(PAGE_SIZE), PAGE_SIZE, PAGE_SIZE));
    try std.testing.expectError(error.InvalidRoot, empty.initialize(0, kernel, expected | (1 << 62), PAGE_SIZE));
    try std.testing.expectError(error.Uninitialized, empty.get(0));
}

test "all sixteen modeled current roots switch independently and retain remote active ownership" {
    const Model = struct {
        hardware: [cpu_identity.MAX_CPUS]usize = @splat(PAGE_SIZE),
        writes: [cpu_identity.MAX_CPUS]u32 = @splat(0),

        fn read(self: *@This()) usize {
            return self.hardware[cpu_identity.currentIndex()];
        }

        fn write(self: *@This(), value: usize) void {
            const index = cpu_identity.currentIndex();
            self.writes[index] += 1;
            self.hardware[index] = value & ~x86.CR3_NO_FLUSH;
        }
    };
    const previous = current_roots;
    const previous_index = cpu_identity.currentIndex();
    defer {
        current_roots = previous;
        cpu_identity.setIndexForTest(previous_index);
    }
    current_roots = .{};
    const kernel: *PageDirectory = @ptrFromInt(virtual_layout.physical_memory.base + PAGE_SIZE);
    var expected: [cpu_identity.MAX_CPUS]*PageDirectory = @splat(kernel);
    var model: Model = .{};
    for (0..cpu_identity.MAX_CPUS) |index| try current_roots.initialize(@intCast(index), kernel, PAGE_SIZE, PAGE_SIZE);
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2);
        cpu_identity.setIndexForTest(index);
        const physical = (@as(usize, index) + 2) * PAGE_SIZE;
        const directory: *PageDirectory = @ptrFromInt(virtual_layout.physical_memory.base + physical);
        const desired = x86.pcidCr3Value(physical, @as(u16, index) + 1, true).?;
        try switchTrackedCurrentRootWith(directory, desired, &model);
        expected[index] = directory;
        try std.testing.expectEqual(directory, try trackedCurrentDirectory());
        try std.testing.expect(current_roots.activeOnAnyCpu(directory));
        try std.testing.expectEqual(@as(u32, 1), model.writes[index]);
        try switchTrackedCurrentRootWith(directory, desired, &model);
        try std.testing.expectEqual(@as(u32, 1), model.writes[index]);
        for (&expected, 0..) |*neighbor, neighbor_index| {
            try std.testing.expectEqual(neighbor.*, try current_roots.get(@intCast(neighbor_index)));
        }
    }
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        const old = expected[index];
        try switchTrackedCurrentRootWith(kernel, PAGE_SIZE, &model);
        expected[index] = kernel;
        try std.testing.expect(!current_roots.activeOnAnyCpu(old));
        try std.testing.expectEqual(kernel, try trackedCurrentDirectory());
        for (&expected, 0..) |*neighbor, neighbor_index|
            try std.testing.expectEqual(neighbor.*, try current_roots.get(@intCast(neighbor_index)));
    }
    try std.testing.expect(current_roots.activeOnAnyCpu(kernel));
}

test "current root switching repairs stale CR3 identity and never publishes failed hardware writes" {
    const Model = struct {
        hardware: usize = PAGE_SIZE,
        writes: u32 = 0,
        fail_write: bool = false,

        fn read(self: *@This()) usize {
            return self.hardware;
        }

        fn write(self: *@This(), value: usize) void {
            self.writes += 1;
            if (!self.fail_write) self.hardware = value & ~x86.CR3_NO_FLUSH;
        }
    };
    var tracker: CurrentRootTracker = .{};
    const kernel: *PageDirectory = @ptrFromInt(virtual_layout.physical_memory.base + PAGE_SIZE);
    const other: *PageDirectory = @ptrFromInt(virtual_layout.physical_memory.base + 2 * PAGE_SIZE);
    var model: Model = .{};
    try std.testing.expectError(error.Uninitialized, tracker.switchWith(0, kernel, PAGE_SIZE, &model));
    try std.testing.expectEqual(@as(u32, 0), model.writes);
    try tracker.initialize(0, kernel, PAGE_SIZE, PAGE_SIZE);
    // A matching software pointer cannot hide a changed root or PCID.
    model.hardware = 2 * PAGE_SIZE;
    try tracker.switchWith(0, kernel, PAGE_SIZE, &model);
    try std.testing.expectEqual(@as(u32, 1), model.writes);
    model.hardware = PAGE_SIZE | 7;
    try tracker.switchWith(0, kernel, PAGE_SIZE, &model);
    try std.testing.expectEqual(@as(u32, 2), model.writes);
    model.fail_write = true;
    try std.testing.expectError(error.HardwareMismatch, tracker.switchWith(0, other, 2 * PAGE_SIZE, &model));
    try std.testing.expectEqual(kernel, try tracker.get(0));
    try std.testing.expect(!tracker.activeOnAnyCpu(other));
    try std.testing.expectError(error.InvalidRoot, tracker.switchWith(0, other, 3 * PAGE_SIZE, &model));
    try std.testing.expectEqual(@as(u32, 3), model.writes);
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

test "kernel image mapping executes only the linker-bounded text pages" {
    const image = KernelImageExtents{
        .text_start = 0x10_0000,
        .text_end = 0x12_0000,
        .immutable_end = 0x18_0000,
        .image_end = 0x20_0000,
    };

    try std.testing.expectEqual(@as(u64, 0), kernelImageLeafFlags(0, image));
    try std.testing.expectEqual(@as(u64, 0), kernelImageLeafFlags(image.image_end, image));

    const text = kernelImageLeafFlags(image.text_start, image);
    try std.testing.expect((text & ENTRY_WRITABLE) == 0);
    try std.testing.expect(table64.isExecutable(text));

    const immutable_data = kernelImageLeafFlags(image.text_end, image);
    try std.testing.expect((immutable_data & ENTRY_WRITABLE) == 0);
    try std.testing.expect(!table64.isExecutable(immutable_data));

    const mutable_data = kernelImageLeafFlags(image.immutable_end, image);
    try std.testing.expect((mutable_data & ENTRY_WRITABLE) != 0);
    try std.testing.expect(!table64.isExecutable(mutable_data));
}

test "precise image mapping retains verification image headroom" {
    try std.testing.expect(PRECISE_IMAGE_LIMIT_MATCHES_LINKER);
    try std.testing.expectEqual(@as(usize, 32), PRECISE_IMAGE_PAGE_TABLES);
    try std.testing.expectEqual(@as(u32, 64 * 1024 * 1024), PRECISE_IMAGE_BYTES);
}

test "kernel direct mapping is non-executable and preserves image immutability" {
    const image = KernelImageExtents{
        .text_start = 0x10_0000,
        .text_end = 0x12_0000,
        .immutable_end = 0x18_0000,
        .image_end = 0x20_0000,
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

test "task roots inherit upper-half kernel mappings without the low AP bridge" {
    var kernel: PageDirectory = @splat(0);
    var task: PageDirectory = @splat(0);
    kernel[0] = tableEntry(0x1000, ENTRY_PRESENT | ENTRY_WRITABLE, TABLE_OWNER_KERNEL_DYNAMIC);
    kernel[1] = tableEntry(0x2000, ENTRY_PRESENT | ENTRY_WRITABLE, TABLE_OWNER_KERNEL_DYNAMIC);
    inline for ([_]usize{ 256, 384, 511 }) |index| kernel[index] = tableEntry(index * PAGE_SIZE, ENTRY_PRESENT | ENTRY_WRITABLE, TABLE_OWNER_INHERITED);
    inheritKernelMappings(&kernel, &task);
    for (task[0..256]) |entry| try std.testing.expectEqual(@as(PageTableEntry, 0), entry);
    try std.testing.expectEqualSlices(PageTableEntry, kernel[256..], task[256..]);
}

test "SIPI reservation selects firmware-available pages before sealing the low aperture" {
    const Allocator = frame_allocator.Fixed(SIPI_PHYSICAL_LIMIT, PAGE_SIZE);
    var storage: Allocator.Storage = undefined;
    var allocator = Allocator.bindStorage(&storage);
    allocator.reset();
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    try std.testing.expect(selectSipiPage(&allocator) == null);
    try allocator.makeAvailable(.{ .base = 0, .count = 1 });
    try std.testing.expect(selectSipiPage(&allocator) == null);
    try allocator.makeAvailable(.{ .base = 0x8000, .count = 1 });
    const candidate = selectSipiPage(&allocator).?;
    try std.testing.expectEqual(@as(u32, 0x8000), candidate);
    try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames });
    try allocator.sealReservations();
    try std.testing.expect(allocator.isReserved(candidate));
    try std.testing.expect(allocator.allocateBelow(1, SIPI_PHYSICAL_LIMIT) == null);
}

test "direct physical aliases cover only the managed aperture" {
    try std.testing.expectEqual(virtual_layout.physical_memory.base, directMapAddress(0).?);
    try std.testing.expectEqual(
        virtual_layout.physical_memory.base + @as(usize, @intCast(MANAGED_PHYSICAL_BYTES - 1)),
        directMapAddress(MANAGED_PHYSICAL_BYTES - 1).?,
    );
    try std.testing.expect(directMapAddress(MANAGED_PHYSICAL_BYTES) == null);
}

const FrameCacheTestSnapshot = if (builtin.is_test) struct {
    frames: [FRAME_CACHE_CPUS][FRAME_CACHE_DEPTH]frame_allocator.PhysicalAddress = undefined,
    lengths: [FRAME_CACHE_CPUS]u8,
    total: FrameCacheTotal,

    fn captureAndClear() @This() {
        var saved = @This(){ .lengths = general_frame_cache_len, .total = general_frame_cache_total };
        for (general_frame_cache_len, 0..) |length, cpu| {
            @memcpy(saved.frames[cpu][0..length], general_frame_cache[cpu][0..length]);
        }
        general_frame_cache_len = @splat(0);
        general_frame_cache_total = 0;
        return saved;
    }

    fn restore(self: *const @This()) void {
        for (self.lengths, 0..) |length, cpu| {
            @memcpy(general_frame_cache[cpu][0..length], self.frames[cpu][0..length]);
        }
        general_frame_cache_len = self.lengths;
        general_frame_cache_total = self.total;
    }
} else struct {};

const CachedFrameAdmissionModel = if (builtin.is_test) struct {
    const Frames = frame_allocator.Fixed(4 * LARGE_2M_PAGE_SIZE, PAGE_SIZE);
    const base: usize = 0x4000_0000;
    const Tables = struct {
        var active: ?*CachedFrameAdmissionModel = null;

        fn table(entry: PageTableEntry) ?*PageTable {
            const model = active orelse return null;
            const physical = entryAddress(entry);
            if (!allocatedSpan(physical, PAGE_SIZE) or physical / PAGE_SIZE >= model.tables.len) return null;
            model.dereferences += 1;
            return &model.tables[physical / PAGE_SIZE];
        }

        fn allocatedSpan(physical: usize, bytes: usize) bool {
            return allocatedPhysicalSpanWith(&(active orelse return false).frames, physical, bytes);
        }

        fn allocated(physical: usize) bool {
            return allocatedSpan(physical, PAGE_SIZE);
        }
    };

    storage: Frames.Storage = undefined,
    frames: Frames = undefined,
    tables: [8]PageTable = @splat(@splat(0)),
    space: UserAddressSpace = undefined,
    root_physical: u64 = 0,
    data_physical: u64 = 0,
    parents: [3]u64 = undefined,
    dereferences: usize = 0,

    fn init(self: *@This()) !void {
        self.* = .{};
        self.frames = Frames.init(&self.storage);
        try self.frames.reserve(.{ .base = 0, .count = 1 });
        self.root_physical = self.frames.allocate(1).?.base;
        self.space = .{ .directory = &self.tables[self.root_physical / PAGE_SIZE], .pcid = 37, .switch_cr3 = @intCast(self.root_physical) };
        var current = self.space.directory;
        for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }, 0..) |shift, level| {
            const physical = self.frames.allocate(1).?.base;
            self.parents[level] = physical;
            current[tableIndex(base, shift)] = tableEntry(@intCast(physical), ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE, TABLE_OWNER_USER_PRIVATE);
            current = &self.tables[physical / PAGE_SIZE];
        }
        self.data_physical = self.frames.allocate(1).?.base;
        self.leaf().* = tableEntry(@intCast(self.data_physical), ENTRY_PRESENT | ENTRY_USER | table64.NO_EXECUTE, PAGE_OWNER_USER_PRIVATE);
        Tables.active = self;
    }

    fn deinit(self: *@This()) void {
        std.debug.assert(Tables.active == self);
        Tables.active = null;
    }

    fn leaf(self: *@This()) *PageTableEntry {
        return &self.tables[self.parents[2] / PAGE_SIZE][tableIndex(base, PAGE_TABLE_SHIFT)];
    }
} else struct {};

test "cached frame admission rejects retained free parents and leaves before dereference or promotion" {
    const saved = FrameCacheTestSnapshot.captureAndClear();
    defer saved.restore();
    const Model = CachedFrameAdmissionModel;
    var model: Model = undefined;
    try model.init();
    defer model.deinit();
    const original = model.leaf().*;
    const before = model.frames.stats();
    for (0..FRAME_CACHE_CPUS) |cpu| {
        for (0..4) |level| {
            const physical = if (level == 3) model.data_physical else model.parents[level];
            try std.testing.expect(stashCpuCachedFrameLocked(cpu, physical));
            try std.testing.expect(model.frames.isAllocated(physical));
            model.dereferences = 0;
            const unchanged = PagePermissions{ .writable = true, .executable = true, .user = false };
            var permissions: ?PagePermissions = unchanged;
            var leaf_end: usize = 0xdead_beef;
            try std.testing.expect(!inspectOwnedUserPreparationPageIntoWith(Model.Tables, model.space.directory, Model.base, false, &permissions, &leaf_end, null));
            try std.testing.expectEqual(@as(?PagePermissions, unchanged), permissions);
            try std.testing.expectEqual(@as(usize, 0xdead_beef), leaf_end);
            try std.testing.expectEqual(@min(level, 3), model.dereferences);
            try std.testing.expectError(error.PageNotOwned, publishOwnedUserWriteWith(Model.Tables, model.space.directory, Model.base));
            try std.testing.expectEqual(original, model.leaf().*);
            try std.testing.expectEqual(before, model.frames.stats());
            // Allocation transfers the actual retained cache entry back to a
            // caller without changing the backing allocator's bitmap count.
            try std.testing.expectEqual(physical, takeCpuCachedFrameLocked(cpu).?);
            try std.testing.expect(!cachedFrame(physical));
            try std.testing.expect(ownedUserPagePermissionsWith(Model.Tables, model.space.directory, Model.base) != null);
        }
    }
    try std.testing.expectEqual(before, model.frames.stats());
    try std.testing.expectEqual(@as(FrameCacheTotal, 0), general_frame_cache_total);
}

test "cached frame admission rejects roots and huge private spans without changing borrowed authority" {
    const saved = FrameCacheTestSnapshot.captureAndClear();
    defer saved.restore();
    const Model = CachedFrameAdmissionModel;
    var model: Model = undefined;
    try model.init();
    defer model.deinit();
    const Root = struct {
        frames: *Model.Frames,
        fn owns(self: *@This(), physical: u64) bool {
            return self.frames.isAllocated(physical) and !cachedFrame(physical);
        }
        fn writableAlias(_: *@This(), physical: u64) ?usize {
            return directMapAddress(physical);
        }
    };
    var root = Root{ .frames = &model.frames };
    const directory = directMapAddress(model.root_physical).?;
    try std.testing.expectEqual(@as(?u64, model.root_physical), checkedUserRootWith(&root, directory, model.space.switch_cr3));
    for (0..FRAME_CACHE_CPUS) |cpu| {
        try std.testing.expect(stashCpuCachedFrameLocked(cpu, model.root_physical));
        try std.testing.expect(checkedUserRootWith(&root, directory, model.space.switch_cr3) == null);
        try std.testing.expectEqual(model.root_physical, takeCpuCachedFrameLocked(cpu).?);
        try std.testing.expectEqual(@as(?u64, model.root_physical), checkedUserRootWith(&root, directory, model.space.switch_cr3));
    }

    // Borrowed RAM authority is supplied by the exact shared-object registry,
    // not private-frame allocation. Its reserved backing is deliberately not
    // admitted as an owned leaf; every parent still needs live table backing.
    const original_leaf = model.leaf().*;
    model.leaf().* = tableEntry(0, ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE | table64.NO_EXECUTE, PAGE_OWNER_BORROWED);
    try std.testing.expect(!model.frames.isAllocated(0));
    try std.testing.expectEqual(SharedUserPageState.present, sharedUserPageStateWith(Model.Tables, model.space.directory, Model.base, 0, true, 0));
    try std.testing.expect(stashCpuCachedFrameLocked(15, model.parents[2]));
    try std.testing.expectEqual(SharedUserPageState.invalid, sharedUserPageStateWith(Model.Tables, model.space.directory, Model.base, 0, true, 0));
    try std.testing.expectEqual(model.parents[2], takeCpuCachedFrameLocked(15).?);
    model.leaf().* = original_leaf;

    const run = model.frames.allocateAlignedBetween(LARGE_2M_FRAME_COUNT, LARGE_2M_FRAME_COUNT, LARGE_2M_PAGE_SIZE, 4 * LARGE_2M_PAGE_SIZE).?;
    const directory_entry = &model.tables[model.parents[1] / PAGE_SIZE][tableIndex(Model.base, PAGE_DIRECTORY_SHIFT)];
    directory_entry.* = tableEntry(@intCast(run.base), ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE | ENTRY_LARGE_PAGE | table64.NO_EXECUTE, PAGE_OWNER_USER_PRIVATE);
    const adjacent = model.frames.allocateFrameBetween(run.base + LARGE_2M_PAGE_SIZE, 4 * LARGE_2M_PAGE_SIZE).?;
    try std.testing.expect(stashCpuCachedFrameLocked(0, model.data_physical));
    try std.testing.expect(stashCpuCachedFrameLocked(1, adjacent));
    const CountingFrames = struct {
        frames: *Model.Frames,
        queries: usize = 0,
        fn isAllocated(self: *@This(), physical: u64) bool {
            self.queries += 1;
            return self.frames.isAllocated(physical);
        }
    };
    var counting = CountingFrames{ .frames = &model.frames };
    for ([_]u64{ run.base, run.base + LARGE_2M_PAGE_SIZE / 2, run.base + LARGE_2M_PAGE_SIZE - PAGE_SIZE }) |physical| {
        try std.testing.expect(stashCpuCachedFrameLocked(15, physical));
        counting.queries = 0;
        try std.testing.expect(!allocatedPhysicalSpanWith(&counting, @intCast(run.base), LARGE_2M_PAGE_SIZE));
        try std.testing.expectEqual(@as(usize, 0), counting.queries);
        var permissions: ?PagePermissions = null;
        var end: usize = 0;
        try std.testing.expect(!inspectOwnedUserPreparationPageIntoWith(Model.Tables, model.space.directory, Model.base, true, &permissions, &end, null));
        try std.testing.expectEqual(physical, takeCpuCachedFrameLocked(15).?);
    }
    // Cache entries immediately outside the span must not remove its authority.
    counting.queries = 0;
    try std.testing.expect(allocatedPhysicalSpanWith(&counting, @intCast(run.base), LARGE_2M_PAGE_SIZE));
    try std.testing.expectEqual(@as(usize, LARGE_2M_FRAME_COUNT), counting.queries);
    var permissions: ?PagePermissions = null;
    var end: usize = 0;
    try std.testing.expect(inspectOwnedUserPreparationPageIntoWith(Model.Tables, model.space.directory, Model.base, true, &permissions, &end, null));
    try std.testing.expect(permissions.?.writable);
    try std.testing.expectEqual(Model.base + LARGE_2M_PAGE_SIZE, end);
    try std.testing.expectEqual(model.data_physical, takeCpuCachedFrameLocked(0).?);
    try std.testing.expectEqual(adjacent, takeCpuCachedFrameLocked(1).?);
}

test "cached frame run release rejects stale cache ownership before freeing any bitmap bit" {
    const saved = FrameCacheTestSnapshot.captureAndClear();
    defer saved.restore();
    const Frames = frame_allocator.Fixed(8 * PAGE_SIZE, PAGE_SIZE);
    var storage: Frames.Storage = undefined;
    var frames = Frames.init(&storage);
    const run = frames.allocate(8).?;
    const cached = 3 * PAGE_SIZE;
    try std.testing.expect(stashCpuCachedFrameLocked(15, cached));
    const before = frames.stats();
    const before_bitmap = storage.unavailable_bitmap;
    const before_words = storage.available_words;
    const before_groups = storage.available_groups;
    var high_zone = false;
    try std.testing.expectError(error.InvalidRun, releaseRunTo(&frames, &high_zone, .{ .base = 0, .count = 0 }, 4 * PAGE_SIZE));
    try std.testing.expectError(error.Unaligned, releaseRunTo(&frames, &high_zone, .{ .base = cached + 1, .count = 1 }, 4 * PAGE_SIZE));
    try std.testing.expectError(error.OutOfRange, releaseRunTo(&frames, &high_zone, .{ .base = 0, .count = 9 }, 4 * PAGE_SIZE));
    try std.testing.expectError(error.NotAllocated, releaseRunTo(&frames, &high_zone, .{ .base = cached, .count = 1 }, 4 * PAGE_SIZE));
    try std.testing.expectError(error.NotAllocated, releaseRunTo(&frames, &high_zone, .{ .base = cached - PAGE_SIZE, .count = 2 }, 4 * PAGE_SIZE));
    try std.testing.expectError(error.NotAllocated, releaseRunTo(&frames, &high_zone, run, 4 * PAGE_SIZE));
    try std.testing.expectEqual(before, frames.stats());
    try std.testing.expectEqualDeep(before_bitmap, storage.unavailable_bitmap);
    try std.testing.expectEqualDeep(before_words, storage.available_words);
    try std.testing.expectEqualDeep(before_groups, storage.available_groups);
    try std.testing.expect(frames.isAllocated(cached) and cachedFrame(cached));
    try std.testing.expect(!high_zone);
    try std.testing.expectEqual(@as(FrameCacheTotal, 1), general_frame_cache_total);
    var cursor = frame_allocator.AllocationCursor{};
    try std.testing.expectEqual(@as(?u64, cached), allocGeneralFrameFrom(&frames, &high_zone, &cursor, 4 * PAGE_SIZE, 8 * PAGE_SIZE));
    try std.testing.expect(!cachedFrame(cached));
    try releaseRunTo(&frames, &high_zone, run, 4 * PAGE_SIZE);
    try std.testing.expect(high_zone);
    try std.testing.expectEqual(@as(u32, 0), frames.stats().allocated);
}

test "full per-CPU frame caches retain ownership and reclaim one contiguous run" {
    const saved = FrameCacheTestSnapshot.captureAndClear();
    defer saved.restore();
    const capacity = FRAME_CACHE_CPUS * FRAME_CACHE_DEPTH;
    const managed_bytes = (capacity + 1) * PAGE_SIZE;
    const low_identity_limit = capacity / 2 * PAGE_SIZE;
    const TestAllocator = frame_allocator.Fixed(managed_bytes, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    _ = allocator.allocate(capacity + 1).?;
    const guard = capacity * PAGE_SIZE;
    const owned = allocator.stats();

    for (0..FRAME_CACHE_CPUS) |cpu| {
        for (0..FRAME_CACHE_DEPTH) |slot| {
            const base = (cpu * FRAME_CACHE_DEPTH + slot) * PAGE_SIZE;
            try std.testing.expect(stashCpuCachedFrameLocked(cpu, base));
            try std.testing.expect(allocator.isAllocated(base));
            try std.testing.expect(cachedFrame(base));
        }
        try std.testing.expectEqual(FRAME_CACHE_DEPTH, general_frame_cache_len[cpu]);
        try std.testing.expect(!stashCpuCachedFrameLocked(cpu, guard));
    }
    try std.testing.expectEqual(@as(FrameCacheTotal, capacity), general_frame_cache_total);
    try std.testing.expectEqual(owned, allocator.stats());
    try std.testing.expect(!cachedFrame(guard));

    // A cache transfer changes reuse ownership without freeing the frame in
    // the backing allocator, even when the aggregate starts at 256 frames.
    const donor = FRAME_CACHE_CPUS - 1;
    const transferred = takeCpuCachedFrameLocked(donor).?;
    try std.testing.expectEqual(@as(FrameCacheTotal, capacity - 1), general_frame_cache_total);
    try std.testing.expect(!cachedFrame(transferred));
    try std.testing.expect(allocator.isAllocated(transferred));
    try std.testing.expect(stashCpuCachedFrameLocked(donor, transferred));
    try std.testing.expectEqual(@as(FrameCacheTotal, capacity), general_frame_cache_total);

    try std.testing.expect(allocator.allocate(capacity) == null);
    var high_zone_has_free_frames = false;
    flushFrameCachesTo(&allocator, &high_zone_has_free_frames, low_identity_limit);
    try std.testing.expect(high_zone_has_free_frames);
    try std.testing.expectEqual(@as(FrameCacheTotal, 0), general_frame_cache_total);
    for (general_frame_cache_len) |length| try std.testing.expectEqual(@as(u8, 0), length);
    for (0..capacity) |index| {
        const base = index * PAGE_SIZE;
        try std.testing.expect(!allocator.isAllocated(base));
        try std.testing.expect(!cachedFrame(base));
    }
    try std.testing.expect(allocator.isAllocated(guard));
    try std.testing.expectEqual(@as(u32, capacity), allocator.stats().free);
    const reclaimed = allocator.allocate(capacity).?;
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, 0), reclaimed.base);
    try std.testing.expectEqual(@as(u32, capacity), reclaimed.count);
    try std.testing.expectEqual(owned, allocator.stats());
    try allocator.release(reclaimed);
    try allocator.releaseFrame(guard);
    try std.testing.expectEqual(@as(u32, capacity + 1), allocator.stats().free);
}

test "general single-frame allocation borrows remote caches only under backing pressure" {
    const saved = FrameCacheTestSnapshot.captureAndClear();
    defer saved.restore();
    const managed_bytes = 8 * PAGE_SIZE;
    const low_identity_limit = 4 * PAGE_SIZE;
    const TestAllocator = frame_allocator.Fixed(managed_bytes, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    _ = allocator.allocate(6).?;
    var high_zone_has_free_frames = true;
    var low_cursor = frame_allocator.AllocationCursor{};
    const donor_cpu = FRAME_CACHE_CPUS - 1;
    general_frame_cache[donor_cpu][0] = 4 * PAGE_SIZE;
    general_frame_cache[donor_cpu][1] = 5 * PAGE_SIZE;
    general_frame_cache_len[donor_cpu] = 2;
    general_frame_cache_total = 2;

    try std.testing.expect(stashCachedFrameLocked(0));
    try std.testing.expectEqual(@as(?frame_allocator.PhysicalAddress, 0), allocGeneralFrameFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        low_identity_limit,
        managed_bytes,
    ));
    try std.testing.expect(high_zone_has_free_frames);
    for ([_]frame_allocator.PhysicalAddress{ 6 * PAGE_SIZE, 7 * PAGE_SIZE }) |expected| {
        try std.testing.expectEqual(@as(?frame_allocator.PhysicalAddress, expected), allocGeneralFrameFrom(
            &allocator,
            &high_zone_has_free_frames,
            &low_cursor,
            low_identity_limit,
            managed_bytes,
        ));
        try std.testing.expectEqual(@as(u8, 2), general_frame_cache_len[donor_cpu]);
    }

    const exhausted = allocator.stats();
    for ([_]frame_allocator.PhysicalAddress{ 5 * PAGE_SIZE, 4 * PAGE_SIZE }, 0..) |expected, index| {
        try std.testing.expect(cachedFrame(expected));
        try std.testing.expectEqual(@as(?frame_allocator.PhysicalAddress, expected), allocGeneralFrameFrom(
            &allocator,
            &high_zone_has_free_frames,
            &low_cursor,
            low_identity_limit,
            managed_bytes,
        ));
        try std.testing.expect(!cachedFrame(expected));
        try std.testing.expectEqual(@as(FrameCacheTotal, @intCast(1 - index)), general_frame_cache_total);
        try std.testing.expectEqual(exhausted, allocator.stats());
    }
    try std.testing.expect(allocGeneralFrameFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        low_identity_limit,
        managed_bytes,
    ) == null);
    try std.testing.expectEqual(@as(u8, 0), general_frame_cache_len[donor_cpu]);
}

test "frame-cache pressure reclamation restores high-memory contiguous allocation" {
    const saved = FrameCacheTestSnapshot.captureAndClear();
    defer saved.restore();
    const managed_bytes = 8 * PAGE_SIZE;
    const low_identity_limit = 4 * PAGE_SIZE;
    const TestAllocator = frame_allocator.Fixed(managed_bytes, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    _ = allocator.allocate(8).?;
    try allocator.releaseFrame(0);
    var high_zone_has_free_frames = true;
    var low_cursor = frame_allocator.AllocationCursor{};
    const donor_cpu = FRAME_CACHE_CPUS - 1;
    general_frame_cache[donor_cpu][0] = 4 * PAGE_SIZE;
    general_frame_cache[donor_cpu][1] = 5 * PAGE_SIZE;
    general_frame_cache_len[donor_cpu] = 2;
    general_frame_cache_total = 2;

    // A high-zone search may cache exhaustion while the last low frame still
    // satisfies an ordinary allocation. The high frames remain in a donor.
    try std.testing.expectEqual(@as(?frame_allocator.PhysicalAddress, 0), allocGeneralFrameFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        low_identity_limit,
        managed_bytes,
    ));
    try std.testing.expect(!high_zone_has_free_frames);
    try std.testing.expectEqual(@as(FrameCacheTotal, 2), general_frame_cache_total);
    try std.testing.expect(allocGeneralRunFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        2,
        low_identity_limit,
        managed_bytes,
    ) == null);
    flushFrameCachesTo(&allocator, &high_zone_has_free_frames, low_identity_limit);
    try std.testing.expect(high_zone_has_free_frames);
    try std.testing.expectEqual(@as(FrameCacheTotal, 0), general_frame_cache_total);
    try std.testing.expectEqual(@as(u8, 0), general_frame_cache_len[donor_cpu]);
    try std.testing.expectEqual(@as(u32, 2), allocator.stats().free);
    const run = allocGeneralRunFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        2,
        low_identity_limit,
        managed_bytes,
    ).?;
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, 4 * PAGE_SIZE), run.base);
    try std.testing.expectEqual(@as(u32, 2), run.count);
    try std.testing.expectEqual(@as(u32, 0), allocator.stats().free);
}

test "low-memory cache reclamation preserves an exhausted high-zone hint" {
    const saved = FrameCacheTestSnapshot.captureAndClear();
    defer saved.restore();
    const TestAllocator = frame_allocator.Fixed(8 * PAGE_SIZE, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    _ = allocator.allocate(8).?;
    var high_zone_has_free_frames = false;
    try std.testing.expect(stashCachedFrameLocked(PAGE_SIZE));
    flushFrameCachesTo(&allocator, &high_zone_has_free_frames, 4 * PAGE_SIZE);
    try std.testing.expect(!high_zone_has_free_frames);
    try std.testing.expectEqual(@as(FrameCacheTotal, 0), general_frame_cache_total);
    try std.testing.expectEqual(@as(u32, 1), allocator.stats().free);
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

test "releasing a run across the identity boundary restores high-memory allocation" {
    const managed_bytes = 8 * PAGE_SIZE;
    const low_identity_limit = 4 * PAGE_SIZE;
    const TestAllocator = frame_allocator.Fixed(managed_bytes, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    _ = allocator.allocate(8).?;
    var high_zone_has_free_frames = false;
    var low_cursor = frame_allocator.AllocationCursor{};

    try releaseRunTo(&allocator, &high_zone_has_free_frames, .{
        .base = 3 * PAGE_SIZE,
        .count = 2,
    }, low_identity_limit);
    try std.testing.expect(high_zone_has_free_frames);
    const run = allocGeneralRunFrom(&allocator, &high_zone_has_free_frames, &low_cursor, 1, low_identity_limit, managed_bytes).?;
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, low_identity_limit), run.base);

    high_zone_has_free_frames = false;
    try std.testing.expectError(error.NotAllocated, releaseRunTo(&allocator, &high_zone_has_free_frames, .{
        .base = 3 * PAGE_SIZE,
        .count = 2,
    }, low_identity_limit));
    try std.testing.expect(!high_zone_has_free_frames);
    try std.testing.expect(allocator.isAllocated(low_identity_limit));

    try releaseRunTo(&allocator, &high_zone_has_free_frames, .{
        .base = 2 * PAGE_SIZE,
        .count = 1,
    }, low_identity_limit);
    try std.testing.expect(!high_zone_has_free_frames);
}

test "sparse direct-map capacity remains bounded to 512 GiB" {
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, 512 * 1024 * 1024 * 1024), MANAGED_PHYSICAL_BYTES);
    try std.testing.expectEqual(@as(usize, 512), DIRECT_MAP_PDPT_ENTRIES);
    try std.testing.expect(SPARSE_CACHE_AWARE_RAM_MAP);
    try std.testing.expectEqual(@as(usize, 4096), efi_handoff.paging_info.MAX_ARENA_PAGES);
    try std.testing.expectEqual(@as(usize, table64.TABLE_ENTRIES), IDENTITY_DIRECTORY_ENTRIES);
}

test "aligned user mappings prefer 2 MiB leaves" {
    try std.testing.expect(USES_RUNTIME_2M_PAGES);
    try std.testing.expectEqual(@as(frame_allocator.PhysicalAddress, 2 * 1024 * 1024), LARGE_2M_PAGE_SIZE);
    try std.testing.expectEqual(@as(u32, 512), LARGE_2M_FRAME_COUNT);
    const permissions = UserPermissions{ .writable = true };
    try std.testing.expectError(error.InvalidRange, ownedUserHugeLeaf(PAGE_SIZE, permissions));
    try std.testing.expectError(error.InvalidRange, ownedUserHugeLeaf(2 * PAGE_SIZE, permissions));
    const aligned = try ownedUserHugeLeaf(LARGE_2M_PAGE_SIZE, permissions);
    try std.testing.expect(table64.isLargePage(aligned));
    try std.testing.expectEqual(@as(usize, LARGE_2M_PAGE_SIZE), entryAddress(aligned));
}

test "huge allocation preserves high-zone availability and falls back without leaking frames" {
    const low_identity_limit = LARGE_2M_PAGE_SIZE;
    const managed_bytes = 2 * LARGE_2M_PAGE_SIZE;
    const TestAllocator = frame_allocator.Fixed(managed_bytes, PAGE_SIZE);
    var storage: TestAllocator.Storage = undefined;
    var allocator = TestAllocator.init(&storage);
    // Both aligned 2 MiB spans contain one unavailable frame, though almost
    // their entire physical memory remains suitable for ordinary user pages.
    try allocator.reserve(.{ .base = 0, .count = 1 });
    try allocator.reserve(.{ .base = low_identity_limit, .count = 1 });
    var high_zone_has_free_frames = true;
    var low_cursor = frame_allocator.AllocationCursor{};
    const before = allocator.stats();
    try std.testing.expect(allocGeneralAlignedRunFrom(
        &allocator,
        high_zone_has_free_frames,
        &low_cursor,
        LARGE_2M_FRAME_COUNT,
        LARGE_2M_FRAME_COUNT,
        low_identity_limit,
        managed_bytes,
    ) == null);
    try std.testing.expectEqual(before, allocator.stats());
    const ordinary = allocGeneralRunFrom(
        &allocator,
        &high_zone_has_free_frames,
        &low_cursor,
        1,
        low_identity_limit,
        managed_bytes,
    ).?;
    try std.testing.expectEqual(low_identity_limit + PAGE_SIZE, ordinary.base);
    try std.testing.expect(high_zone_has_free_frames);
    try allocator.release(ordinary);
    try std.testing.expectEqual(before, allocator.stats());
}

test "leaf mappings encode global and execute permissions explicitly" {
    const kernel_leaf = leafFlags(PAGE_PRESENT | PAGE_WRITABLE, true);
    try std.testing.expect((kernel_leaf & table64.NO_EXECUTE) != 0);
    try std.testing.expect((kernel_leaf & ENTRY_GLOBAL) != 0);

    const user_leaf = leafFlags(PAGE_PRESENT | PAGE_USER | PAGE_EXECUTABLE, false);
    try std.testing.expect((user_leaf & table64.NO_EXECUTE) == 0);
    try std.testing.expect((user_leaf & ENTRY_GLOBAL) == 0);
}

const TestUserWriteBatch = if (builtin.is_test) UserWriteBatch else void;
const TestUserPermissions = if (builtin.is_test) UserPermissions else void;
const TestPagePermissions = if (builtin.is_test) PagePermissions else void;

// This test backend drives the production walker, release publication, batch
// state and context invalidation; only physical storage/hardware are modeled.
pub const WritePreparationTestPaging = if (builtin.is_test) struct {
    pub const Model = struct {
        const Frames = frame_allocator.Fixed(4 * LARGE_2M_PAGE_SIZE, PAGE_SIZE);
        pub const base: usize = 0x4000_0000;
        const Tables = struct {
            var active: ?*Model = null;

            fn table(entry: PageTableEntry) ?*PageTable {
                const model = active orelse return null;
                model.table_lookups += 1;
                const physical = entryAddress(entry);
                if (physical >= model.tables.len * PAGE_SIZE or !allocated(physical)) return null;
                return &model.tables[physical / PAGE_SIZE];
            }

            fn allocated(physical: usize) bool {
                return allocatedSpan(physical, PAGE_SIZE);
            }

            fn allocatedSpan(physical: usize, span_bytes: usize) bool {
                const model = active orelse return false;
                if (physical >= 4 * LARGE_2M_PAGE_SIZE or span_bytes > 4 * LARGE_2M_PAGE_SIZE - physical) return false;
                if (span_bytes == LARGE_2M_PAGE_SIZE) model.huge_span_queries += 1;
                var address = physical;
                while (address < physical + span_bytes) : (address += PAGE_SIZE) {
                    if (!model.frames.isAllocated(address)) return false;
                }
                return true;
            }
        };

        storage: Frames.Storage = undefined,
        frames: Frames = undefined,
        tables: [16]PageTable = @splat(@splat(0)),
        payload: [16][PAGE_SIZE]u8 = @splat(@splat(0xA5)),
        space: UserAddressSpace = undefined,
        root_physical: u64 = 0,
        data: [3]u64 = undefined,
        original: [3]PageTableEntry = undefined,
        expected_writable: u3 = 0,
        table_lookups: usize = 0,
        barriers: usize = 0,
        local_count: usize = 0,
        reload_count: usize = 0,
        remote_count: usize = 0,
        acknowledged: bool = false,
        valid: bool = true,
        identifiers_enabled: bool = true,
        active: bool = true,
        fail_allocation: bool = false,
        allocation_budget: usize = std.math.maxInt(usize),
        materializations: usize = 0,
        huge_span_queries: usize = 0,
        cpu: u8 = 0,
        interrupts_enabled: bool = false,

        pub fn init(self: *@This()) !void {
            self.* = .{};
            self.frames = Frames.init(&self.storage);
            try self.frames.reserve(.{ .base = 0, .count = 1 });
            try self.frames.sealReservations();
            self.root_physical = self.frames.allocate(1).?.base;
            self.space = .{ .directory = &self.tables[self.root_physical / PAGE_SIZE], .pcid = 37, .switch_cr3 = @intCast(self.root_physical) };
            Tables.active = self;
            var current = self.space.directory;
            for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }) |shift| {
                const physical = self.frames.allocate(1).?.base;
                current[tableIndex(base, shift)] = tableEntry(@intCast(physical), ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE, TABLE_OWNER_USER_PRIVATE);
                current = &self.tables[physical / PAGE_SIZE];
            }
            for (&self.data, 0..) |*physical, index| {
                physical.* = self.frames.allocate(1).?.base;
                const flags = ENTRY_PRESENT | ENTRY_USER | table64.NO_EXECUTE | PAGE_ACCESSED | PAGE_DIRTY;
                const initial = table64.withProtectionKey(tableEntry(@intCast(physical.*), flags, PAGE_OWNER_USER_PRIVATE), 3);
                self.leaf(base + index * PAGE_SIZE).* = initial;
                self.original[index] = initial;
            }
        }

        pub fn deinit(self: *@This()) void {
            std.debug.assert(Tables.active == self);
            Tables.active = null;
        }

        pub fn leaf(self: *@This(), address: usize) *PageTableEntry {
            var current = self.space.directory;
            for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }) |shift|
                current = &self.tables[entryAddress(current[tableIndex(address, shift)]) / PAGE_SIZE];
            return &current[tableIndex(address, PAGE_TABLE_SHIFT)];
        }

        fn invalidate(self: *@This(), space: *const UserAddressSpace) void {
            if (space != &self.space) self.valid = false;
            self.barriers += 1;
            invalidateUserContextWith(self, space.pcid, self.identifiers_enabled, self.active);
        }

        fn invalidatePcid(self: *@This(), identifier: u16) void {
            if (identifier != self.space.pcid or self.remote_count >= self.barriers) self.valid = false;
            self.local_count += 1;
        }

        fn reloadCurrentRoot(self: *@This()) void {
            if (self.remote_count >= self.barriers) self.valid = false;
            self.reload_count += 1;
        }

        fn invalidateRemote(self: *@This(), identifier: u16) void {
            if (identifier != self.space.pcid) self.valid = false;
            for (0..3) |index| {
                if (self.expected_writable & (@as(u3, 1) << @as(u2, @intCast(index))) == 0) continue;
                const observed = @atomicLoad(PageTableEntry, self.leaf(base + index * PAGE_SIZE), .acquire);
                if (observed != self.original[index] | ENTRY_WRITABLE or !self.frames.isAllocated(self.data[index])) self.valid = false;
            }
            self.remote_count += 1;
            self.acknowledged = true;
        }

        pub fn installHuge(self: *@This()) !void {
            var directory = self.space.directory;
            for ([_]u6{ PML4_SHIFT, PDPT_SHIFT }) |shift|
                directory = &self.tables[entryAddress(directory[tableIndex(base, shift)]) / PAGE_SIZE];
            const entry = &directory[tableIndex(base, PAGE_DIRECTORY_SHIFT)];
            try self.frames.release(.{ .base = entryAddress(entry.*), .count = 1 });
            for (self.data) |physical| try self.frames.release(.{ .base = physical, .count = 1 });
            const run = self.frames.allocateAlignedBetween(LARGE_2M_FRAME_COUNT, LARGE_2M_FRAME_COUNT, LARGE_2M_PAGE_SIZE, 4 * LARGE_2M_PAGE_SIZE).?;
            entry.* = tableEntry(@intCast(run.base), ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE | ENTRY_LARGE_PAGE | table64.NO_EXECUTE, PAGE_OWNER_USER_PRIVATE);
        }

        pub fn retire(self: *@This()) void {
            const Retirement = struct {
                model: *Model,
                retired: bool = false,

                fn table(backend: *@This(), entry: PageTableEntry) *PageTable {
                    return &backend.model.tables[entryAddress(entry) / PAGE_SIZE];
                }

                fn invalidate(backend: *@This()) void {
                    if (backend.model.barriers != 0 and !backend.model.acknowledged) backend.model.valid = false;
                    backend.retired = true;
                }

                fn release(backend: *@This(), physical: u64, count: u32) void {
                    if (!backend.retired) backend.model.valid = false;
                    backend.model.frames.release(.{ .base = physical, .count = count }) catch unreachable;
                }
            };
            var retirement = Retirement{ .model = self };
            retireOwnedHierarchy(&retirement, self.space.directory, self.root_physical);
        }

        fn materialize(self: *@This(), address: usize, permissions: TestUserPermissions) UserMapError!void {
            self.materializations += 1;
            const Mapping = struct {
                model: *Model,

                fn leaf(mapping: @This(), virtual: usize) UserMapError!*PageTableEntry {
                    return mapping.model.leaf(virtual);
                }

                fn allocate(mapping: @This()) ?u64 {
                    return mapping.model.allocate();
                }

                fn bytes(mapping: @This(), physical: u64) *[PAGE_SIZE]u8 {
                    return mapping.model.bytes(physical);
                }
            };
            return initializeOwnedUserPage(Mapping{ .model = self }, address, permissions, null);
        }

        fn allocate(self: *@This()) ?u64 {
            if (self.fail_allocation or self.allocation_budget == 0) return null;
            self.allocation_budget -= 1;
            return if (self.frames.allocate(1)) |run| run.base else null;
        }

        fn bytes(self: *@This(), physical: u64) *[PAGE_SIZE]u8 {
            return &self.payload[physical / PAGE_SIZE];
        }
    };

    pub const UserPermissions = TestUserPermissions;
    pub const PagePermissions = TestPagePermissions;
    pub const UserWriteBatch = struct {
        actual: TestUserWriteBatch,
        model: *Model,

        pub fn initInto(model: *Model, out: *@This()) bool {
            var actual: TestUserWriteBatch = undefined;
            if (!TestUserWriteBatch.initIntoWith(&model.space, &actual, model.cpu, model.interrupts_enabled)) return false;
            out.* = .{ .actual = actual, .model = model };
            return true;
        }

        pub fn promote(self: *@This(), address: usize) UserWriteError!bool {
            return self.actual.promoteWith(Model.Tables, address);
        }

        pub fn finish(self: *@This()) void {
            self.actual.finishWith(self.model);
        }
    };

    pub fn inspectOwnedUserPreparationPageInto(model: *Model, address: usize, write: bool, out: *?TestPagePermissions, leaf_end: *usize) bool {
        return inspectOwnedUserPreparationPageIntoWith(Model.Tables, model.space.directory, address, write, out, leaf_end, null);
    }

    pub fn mapOwnedUserRange(model: *Model, address: usize, _: usize, permissions: TestUserPermissions) UserMapError!void {
        return model.materialize(address, permissions);
    }

    pub fn mapBorrowedPhysicalUserRange(_: *Model, _: usize, _: u64, _: usize, _: TestUserPermissions) UserMapError!void {
        return error.KernelMappingCollision;
    }

    pub fn mapOwnedUserPageFromPhysical(model: *Model, address: usize, _: u64, permissions: TestUserPermissions) UserMapError!void {
        return model.materialize(address, permissions);
    }

    pub fn promoteOwnedUserPageForWrite(model: *Model, address: usize) UserWriteError!bool {
        return promoteOwnedUserWriteWith(Model.Tables, model, &model.space, address);
    }
} else struct {};

test "private write batch admission and finish preserve clean or rejected state" {
    var directory: PageDirectory = @splat(0);
    const space = UserAddressSpace{ .directory = &directory, .pcid = 37, .switch_cr3 = 0x1000 };
    var batch = UserWriteBatch{ .space = &space, .changed = true };
    for (1..cpu_identity.MAX_CPUS) |cpu| {
        try std.testing.expect(!UserWriteBatch.initIntoWith(&space, &batch, @intCast(cpu), false));
        try std.testing.expect(batch.changed);
    }
    try std.testing.expect(!UserWriteBatch.initIntoWith(&space, &batch, 0, true));
    try std.testing.expect(batch.changed);
    try std.testing.expect(UserWriteBatch.initIntoWith(&space, &batch, 0, false));
    const Observer = struct {
        count: usize = 0,

        fn invalidate(self: *@This(), _: *const UserAddressSpace) void {
            self.count += 1;
        }
    };
    var observer = Observer{};
    batch.finishWith(&observer);
    try std.testing.expectEqual(@as(usize, 0), observer.count);
    batch.changed = true;
    batch.finishWith(&observer);
    batch.finishWith(&observer);
    try std.testing.expectEqual(@as(usize, 1), observer.count);
}

test "private write promotion rejects every forged parent and leaves flags unchanged" {
    const Model = WritePreparationTestPaging.Model;
    var model: Model = undefined;
    try model.init();
    defer model.deinit();
    const original_pointer = model.leaf(Model.base);
    const original_leaf = original_pointer.*;
    var current = model.space.directory;
    for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }, 0..) |shift, level| {
        const parent = &current[tableIndex(Model.base, shift)];
        const valid = parent.*;
        for ([_]u64{
            valid & ~ENTRY_PRESENT,
            valid & ~ENTRY_USER,
            valid & ~ENTRY_WRITABLE,
            valid | ENTRY_LARGE_PAGE,
            valid | ENTRY_WRITE_THROUGH,
            valid | ENTRY_CACHE_DISABLE,
            valid | ENTRY_GLOBAL,
            valid | (@as(u64, 1) << 54),
            table64.withOwner(valid, TABLE_OWNER_INHERITED),
            table64.withProtectionKey(valid, 3),
            tableEntry(15 * PAGE_SIZE, ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE, TABLE_OWNER_USER_PRIVATE),
        }) |forged| {
            parent.* = forged;
            model.table_lookups = 0;
            try std.testing.expectError(error.PageNotOwned, publishOwnedUserWriteWith(Model.Tables, model.space.directory, Model.base));
            try std.testing.expect(model.table_lookups <= level + 1);
            try std.testing.expectEqual(original_leaf, original_pointer.*);
        }
        parent.* = valid;
        current = Model.Tables.table(valid).?;
    }
    for ([_]usize{ Model.base + 1, 0x0000_8000_0000_0000, 0xFFFF_8000_0000_0000 }) |invalid|
        try std.testing.expectError(error.InvalidRange, publishOwnedUserWriteWith(Model.Tables, model.space.directory, invalid));
    const leaf = model.leaf(Model.base);
    for ([_]u64{
        original_leaf & ~ENTRY_PRESENT,
        original_leaf & ~ENTRY_USER,
        original_leaf & ~table64.NO_EXECUTE,
        original_leaf | ENTRY_LARGE_PAGE,
        original_leaf | ENTRY_CACHE_DISABLE,
        original_leaf | ENTRY_WRITE_THROUGH,
        original_leaf | ENTRY_GLOBAL,
        original_leaf | (@as(u64, 1) << 54),
        table64.withOwner(original_leaf, PAGE_OWNER_BORROWED),
        tableEntry(15 * PAGE_SIZE, ENTRY_PRESENT | ENTRY_USER | table64.NO_EXECUTE, PAGE_OWNER_USER_PRIVATE),
    }) |forged| {
        leaf.* = forged;
        try std.testing.expectError(error.PageNotOwned, publishOwnedUserWriteWith(Model.Tables, model.space.directory, Model.base));
        try std.testing.expectEqual(forged, leaf.*);
    }
    leaf.* = original_leaf;
    model.expected_writable = 1;
    try std.testing.expect(try promoteOwnedUserWriteWith(Model.Tables, &model, &model.space, Model.base));
    try std.testing.expect(model.valid and model.acknowledged);
    try std.testing.expectEqual(original_leaf | ENTRY_WRITABLE, leaf.*);
    try std.testing.expectEqual(@as(usize, 1), model.barriers);
    model.retire();
}

test "owned user huge permission inspection checks the complete allocated leaf span" {
    const Frames = frame_allocator.Fixed(4 * LARGE_2M_PAGE_SIZE, PAGE_SIZE);
    const Tables = struct {
        var storage: [2]PageTable = @splat(@splat(0));
        var frames: ?*Frames = null;

        fn table(entry: PageTableEntry) ?*PageTable {
            return switch (entryAddress(entry)) {
                PAGE_SIZE => &storage[0],
                2 * PAGE_SIZE => &storage[1],
                else => null,
            };
        }

        fn allocatedSpan(start: usize, bytes: usize) bool {
            var address = start;
            while (address < start + bytes) : (address += PAGE_SIZE) {
                if (!frames.?.isAllocated(address)) return false;
            }
            return true;
        }
    };
    defer {
        Tables.frames = null;
        Tables.storage = @splat(@splat(0));
    }
    var storage: Frames.Storage = undefined;
    var frames = Frames.init(&storage);
    const run = frames.allocateAlignedBetween(LARGE_2M_FRAME_COUNT, LARGE_2M_FRAME_COUNT, LARGE_2M_PAGE_SIZE, 4 * LARGE_2M_PAGE_SIZE).?;
    Tables.frames = &frames;
    var root: PageDirectory = @splat(0);
    const flags = ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE;
    root[0] = tableEntry(PAGE_SIZE, flags, TABLE_OWNER_USER_PRIVATE);
    Tables.storage[0][1] = tableEntry(2 * PAGE_SIZE, flags, TABLE_OWNER_USER_PRIVATE);
    const huge = tableEntry(@intCast(run.base), flags | ENTRY_LARGE_PAGE | table64.NO_EXECUTE, PAGE_OWNER_USER_PRIVATE);
    Tables.storage[1][0] = huge;
    var permissions: ?PagePermissions = null;
    var leaf_end: usize = undefined;
    try std.testing.expect(inspectOwnedUserPreparationPageIntoWith(Tables, &root, 0x4000_0123, true, &permissions, &leaf_end, null));
    try std.testing.expect(permissions.?.writable);
    // A missing middle frame must fail; checking endpoints is insufficient.
    try frames.release(.{ .base = run.base + 255 * PAGE_SIZE, .count = 1 });
    try std.testing.expect(!inspectOwnedUserPreparationPageIntoWith(Tables, &root, 0x4000_0123, false, &permissions, &leaf_end, null));
    Tables.storage[1][0] = huge & ~ENTRY_WRITABLE;
    try std.testing.expect(!inspectOwnedUserPreparationPageIntoWith(Tables, &root, 0x4000_0123, true, &permissions, &leaf_end, null));
    try std.testing.expectEqual(huge & ~ENTRY_WRITABLE, Tables.storage[1][0]);
}

test "private-copy promotion changes only writable owned user data leaves" {
    const original = tableEntry(0x2000, ENTRY_PRESENT | ENTRY_USER | table64.NO_EXECUTE, PAGE_OWNER_USER_PRIVATE);
    const promoted = try writablePrivateUserLeaf(original);
    try std.testing.expectEqual(original | ENTRY_WRITABLE, promoted);
    try std.testing.expectEqual(promoted, try writablePrivateUserLeaf(promoted));
    for ([_]PageTableEntry{
        0,
        original & ~ENTRY_PRESENT,
        original & ~ENTRY_USER,
        original & ~table64.NO_EXECUTE,
        original | ENTRY_LARGE_PAGE,
        table64.withOwner(original, PAGE_OWNER_BORROWED),
    }) |invalid| {
        try std.testing.expectError(error.PageNotOwned, writablePrivateUserLeaf(invalid));
    }
}

test "user copy permissions validate private hierarchy and effective leaf permissions" {
    const Tables = struct {
        var storage: [3]PageTable = @splat(@splat(0));

        fn allocatedSpan(physical: usize, bytes: usize) bool {
            return (physical == 0x8000 and bytes == PAGE_SIZE) or
                (physical == 0x400000 and bytes == LARGE_2M_PAGE_SIZE);
        }

        fn table(entry: PageTableEntry) ?*PageTable {
            return switch (entryAddress(entry)) {
                0x1000 => &storage[0],
                0x2000 => &storage[1],
                0x3000 => &storage[2],
                else => null,
            };
        }
    };
    defer Tables.storage = @splat(@splat(0));
    var directory: PageDirectory = @splat(0);
    const virtual_address = 0x4040_3011;
    const flags = ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE;
    directory[0] = tableEntry(0x1000, flags, TABLE_OWNER_USER_PRIVATE);
    Tables.storage[0][1] = tableEntry(0x2000, flags, TABLE_OWNER_USER_PRIVATE);
    Tables.storage[1][2] = tableEntry(0x3000, flags, TABLE_OWNER_USER_PRIVATE);
    const leaf = tableEntry(0x8000, flags | table64.NO_EXECUTE, PAGE_OWNER_USER_PRIVATE);
    Tables.storage[2][3] = leaf;
    try std.testing.expectEqualDeep(PagePermissions{ .writable = true, .executable = false, .user = true }, ownedUserPagePermissionsWith(Tables, &directory, virtual_address).?);

    directory[0] &= ~ENTRY_WRITABLE;
    try std.testing.expect(!ownedUserPagePermissionsWith(Tables, &directory, virtual_address).?.writable);
    directory[0] |= ENTRY_WRITABLE | table64.NO_EXECUTE;
    Tables.storage[2][3] = leaf & ~table64.NO_EXECUTE;
    try std.testing.expect(!ownedUserPagePermissionsWith(Tables, &directory, virtual_address).?.executable);
    directory[0] &= ~table64.NO_EXECUTE;
    try std.testing.expect(ownedUserPagePermissionsWith(Tables, &directory, virtual_address).?.executable);
    directory[0] &= ~ENTRY_USER;
    try std.testing.expect(ownedUserPagePermissionsWith(Tables, &directory, virtual_address) == null);
    directory[0] |= ENTRY_USER;
    Tables.storage[0][1] = table64.withOwner(Tables.storage[0][1], TABLE_OWNER_INHERITED);
    try std.testing.expect(ownedUserPagePermissionsWith(Tables, &directory, virtual_address) == null);
    Tables.storage[0][1] = table64.withOwner(Tables.storage[0][1], TABLE_OWNER_USER_PRIVATE);

    for ([_]PageTableEntry{
        leaf & ~ENTRY_PRESENT,
        leaf & ~ENTRY_USER,
        table64.withOwner(leaf, PAGE_OWNER_BORROWED),
        table64.withOwner(leaf, PAGE_OWNER_RETIRED_PRIVATE),
        leaf | ENTRY_LARGE_PAGE,
        tableEntry(MANAGED_PHYSICAL_BYTES, flags, PAGE_OWNER_USER_PRIVATE),
    }) |invalid| {
        Tables.storage[2][3] = invalid;
        try std.testing.expect(ownedUserPagePermissionsWith(Tables, &directory, virtual_address) == null);
    }
    Tables.storage[1][2] = tableEntry(0x400000, flags | ENTRY_LARGE_PAGE, PAGE_OWNER_USER_PRIVATE);
    try std.testing.expect(ownedUserPagePermissionsWith(Tables, &directory, virtual_address).?.writable);
    Tables.storage[1][2] = tableEntry(0x401000, flags | ENTRY_LARGE_PAGE, PAGE_OWNER_USER_PRIVATE);
    try std.testing.expect(ownedUserPagePermissionsWith(Tables, &directory, virtual_address) == null);
    Tables.storage[0][1] = tableEntry(0x40000000, flags | ENTRY_LARGE_PAGE, PAGE_OWNER_USER_PRIVATE);
    try std.testing.expect(ownedUserPagePermissionsWith(Tables, &directory, virtual_address) == null);
    try std.testing.expect(ownedUserPagePermissionsWith(Tables, &directory, 0x0000_8000_0000_0000) == null);
}

const SharedCopyWalkModel = struct {
    const Frames = frame_allocator.Fixed(32 * PAGE_SIZE, PAGE_SIZE);
    const virtual: usize = 0x4000_0000;
    const physical: u64 = 8 * PAGE_SIZE;
    const Tables = struct {
        var storage: [32]PageTable = @splat(@splat(0));
        var active: ?*SharedCopyWalkModel = null;

        fn allocatedSpan(start: usize, bytes: usize) bool {
            const model = active orelse return false;
            if (start >= 32 * PAGE_SIZE or bytes > 32 * PAGE_SIZE - start) return false;
            var address = start;
            while (address < start + bytes) : (address += PAGE_SIZE) {
                if (!model.frames.isAllocated(address)) return false;
            }
            return true;
        }

        fn table(entry: PageTableEntry) ?*PageTable {
            const address = entryAddress(entry);
            const model = active orelse return null;
            if (!model.frames.isAllocated(address)) return null;
            return &storage[address / PAGE_SIZE];
        }
    };

    frame_storage: Frames.Storage = undefined,
    frames: Frames = undefined,
    root_physical: u64 = 0,
    backing: [3 * PAGE_SIZE]u8 = @splat(0xA7),
    allocations: usize = 0,
    fail_after: usize = std.math.maxInt(usize),
    publications: usize = 0,
    invalidations: usize = 0,
    aliases_allowed: bool = true,

    fn init(self: *@This()) !void {
        self.* = .{};
        self.frames = Frames.init(&self.frame_storage);
        Tables.storage = @splat(@splat(0));
        Tables.active = self;
        try self.frames.reserve(.{ .base = 0, .count = 1 });
        try self.frames.reserve(.{ .base = physical, .count = 3 });
        try self.frames.sealReservations();
        self.root_physical = self.frames.allocate(1).?.base;
    }

    fn root(self: *@This()) *PageDirectory {
        return &Tables.storage[self.root_physical / PAGE_SIZE];
    }

    fn state(self: *@This(), address: usize, expected: u64, write: bool, key: u4) SharedUserPageState {
        return sharedUserPageStateWith(Tables, self.root(), address, expected, write, key);
    }

    fn alias(self: *@This(), address: u64, bytes: usize, _: bool) ?usize {
        const end = std.math.add(u64, address, bytes) catch return null;
        if (!self.aliases_allowed or address < physical or end > physical + self.backing.len) return null;
        return @intFromPtr(&self.backing) + address - physical;
    }

    fn allocate(self: *@This()) ?u64 {
        if (self.allocations >= self.fail_after) return null;
        const frame = self.frames.allocate(1) orelse return null;
        self.allocations += 1;
        return frame.base;
    }

    fn table(_: *@This(), entry: PageTableEntry) *PageTable {
        return Tables.table(entry).?;
    }

    fn optionalTable(_: *@This(), entry: PageTableEntry) ?*PageTable {
        return Tables.table(entry);
    }

    fn map(self: *@This(), address: usize, expected: u64) bool {
        return mapSharedBorrowedPageWith(self, address, expected);
    }

    fn publish(self: *@This(), entry: *PageTableEntry, value: PageTableEntry, _: usize) void {
        self.publications += 1;
        @atomicStore(PageTableEntry, entry, value, .release);
    }

    fn leaf(self: *@This(), address: usize) *PageTableEntry {
        var current = self.root();
        for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }) |shift|
            current = Tables.table(current[tableIndex(address, shift)]).?;
        return &current[tableIndex(address, PAGE_TABLE_SHIFT)];
    }

    fn invalidate(self: *@This()) void {
        self.invalidations += 1;
    }

    fn release(self: *@This(), address: u64, count: u32) void {
        self.frames.release(.{ .base = address, .count = count }) catch unreachable;
    }
};

test "shared copy walk materializes only exact borrowed WB data and preserves read parent permissions" {
    var model: SharedCopyWalkModel = undefined;
    try model.init();
    defer SharedCopyWalkModel.Tables.active = null;
    const start = SharedCopyWalkModel.virtual + PAGE_SIZE - 16;
    const physical = SharedCopyWalkModel.physical + PAGE_SIZE - 16;
    const before = model.frames.stats();
    const alias = prepareSharedPhysicalUserRangeWith(&model, start, physical, 32, true, 0).?;
    try std.testing.expectEqual(@intFromPtr(&model.backing) + PAGE_SIZE - 16, alias);
    try std.testing.expectEqual(@as(usize, 3), model.allocations);
    try std.testing.expectEqual(@as(usize, 2), model.publications);
    try std.testing.expectEqual(before.allocated + 3, model.frames.stats().allocated);
    try std.testing.expectEqual(SharedUserPageState.present, model.state(start, SharedCopyWalkModel.physical, true, 0));
    try std.testing.expect(ownedUserPagePermissionsWith(SharedCopyWalkModel.Tables, model.root(), start) == null);
    const data: *[32]u8 = @ptrFromInt(alias);
    @memset(data, 0x39);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x39)), model.backing[PAGE_SIZE - 16 .. PAGE_SIZE + 16]);
    try std.testing.expectEqual(@as(u8, 0xA7), model.backing[PAGE_SIZE - 17]);
    try std.testing.expectEqual(@as(u8, 0xA7), model.backing[PAGE_SIZE + 16]);
    model.root()[0] &= ~ENTRY_WRITABLE;
    const original_parent = model.root()[0];
    try std.testing.expect(prepareSharedPhysicalUserRangeWith(&model, SharedCopyWalkModel.virtual + 2 * PAGE_SIZE, SharedCopyWalkModel.physical + 2 * PAGE_SIZE, 1, false, 0) != null);
    try std.testing.expectEqual(original_parent, model.root()[0]);
    try std.testing.expect(prepareSharedPhysicalUserRangeWith(&model, start, physical, 32, true, 0) == null);
    retireOwnedHierarchy(&model, model.root(), model.root_physical);
    try std.testing.expectEqual(@as(u32, 0), model.frames.stats().allocated);
    try std.testing.expectEqual(@as(usize, 1), model.invalidations);
}

test "shared copy preflight rejects forged late leaves before materialization or payload" {
    var model: SharedCopyWalkModel = undefined;
    try model.init();
    defer SharedCopyWalkModel.Tables.active = null;
    try std.testing.expect(model.map(SharedCopyWalkModel.virtual + PAGE_SIZE, SharedCopyWalkModel.physical + PAGE_SIZE));
    const late = model.leaf(SharedCopyWalkModel.virtual + PAGE_SIZE);
    const valid = late.*;
    const allocations = model.allocations;
    const publications = model.publications;
    const untouched = model.backing;
    for ([_]u64{
        valid + PAGE_SIZE,
        table64.withOwner(valid, PAGE_OWNER_USER_PRIVATE),
        table64.withOwner(valid, PAGE_OWNER_RETIRED_BORROWED),
        valid & ~ENTRY_PRESENT,
        valid & ~ENTRY_USER,
        valid & ~ENTRY_WRITABLE,
        valid & ~table64.NO_EXECUTE,
        valid | ENTRY_LARGE_PAGE,
        valid | ENTRY_CACHE_DISABLE,
        valid | ENTRY_WRITE_THROUGH,
        valid | ENTRY_GLOBAL,
        valid | (@as(u64, 1) << 55),
        table64.withProtectionKey(valid, 3),
    }) |forged| {
        late.* = forged;
        var output: [32]u8 = @splat(0x5B);
        if (prepareSharedPhysicalUserRangeWith(&model, SharedCopyWalkModel.virtual + PAGE_SIZE - 16, SharedCopyWalkModel.physical + PAGE_SIZE - 16, output.len, true, 0)) |alias|
            @memcpy(&output, @as([*]const u8, @ptrFromInt(alias))[0..output.len]);
        try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x5B)), &output);
        try std.testing.expectEqualSlices(u8, &untouched, &model.backing);
        try std.testing.expectEqual(@as(u64, 0), model.leaf(SharedCopyWalkModel.virtual).*);
        try std.testing.expectEqual(allocations, model.allocations);
        try std.testing.expectEqual(publications, model.publications);
    }
    late.* = valid;
    retireOwnedHierarchy(&model, model.root(), model.root_physical);
    try std.testing.expectEqual(@as(u32, 0), model.frames.stats().allocated);
}

test "shared copy rejects every forged parent and huge hierarchy without following it" {
    var model: SharedCopyWalkModel = undefined;
    try model.init();
    defer SharedCopyWalkModel.Tables.active = null;
    try std.testing.expect(model.map(SharedCopyWalkModel.virtual, SharedCopyWalkModel.physical));
    var current = model.root();
    for ([_]u6{ PML4_SHIFT, PDPT_SHIFT, PAGE_DIRECTORY_SHIFT }) |shift| {
        const entry = &current[tableIndex(SharedCopyWalkModel.virtual, shift)];
        const valid = entry.*;
        for ([_]u64{
            valid & ~ENTRY_USER,
            valid & ~ENTRY_WRITABLE,
            valid & ~ENTRY_PRESENT,
            valid | ENTRY_LARGE_PAGE,
            valid | ENTRY_WRITE_THROUGH,
            valid | ENTRY_CACHE_DISABLE,
            valid | ENTRY_GLOBAL,
            valid | (@as(u64, 1) << 54),
            table64.withOwner(valid, TABLE_OWNER_INHERITED),
            table64.withProtectionKey(valid, 2),
            tableEntry(0x1F000, ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER, TABLE_OWNER_USER_PRIVATE),
        }) |forged| {
            entry.* = forged;
            try std.testing.expect(prepareSharedPhysicalUserRangeWith(&model, SharedCopyWalkModel.virtual, SharedCopyWalkModel.physical, 1, true, 0) == null);
        }
        entry.* = valid;
        current = SharedCopyWalkModel.Tables.table(valid).?;
    }
    model.aliases_allowed = false;
    try std.testing.expect(prepareSharedPhysicalUserRangeWith(&model, SharedCopyWalkModel.virtual, SharedCopyWalkModel.physical, 1, true, 0) == null);
    try std.testing.expect(prepareSharedPhysicalUserRangeWith(&model, SharedCopyWalkModel.virtual, SharedCopyWalkModel.physical + 1, 1, false, 0) == null);
    try std.testing.expect(prepareSharedPhysicalUserRangeWith(&model, SharedCopyWalkModel.virtual, SharedCopyWalkModel.physical, 1, false, 3) == null);
    retireOwnedHierarchy(&model, model.root(), model.root_physical);
}

test "shared copy table exhaustion exposes no alias and root retirement reclaims partial tables" {
    var model: SharedCopyWalkModel = undefined;
    defer SharedCopyWalkModel.Tables.active = null;
    for ([_]usize{ 2, 3 }) |limit| {
        try model.init();
        const baseline = model.frames.stats();
        const untouched = model.backing;
        model.fail_after = limit;
        var output: [32]u8 = @splat(0xC4);
        // The late case publishes the first page, then runs out of memory at
        // the next 2 MiB table boundary. Neither case may expose payload bytes.
        if (prepareSharedPhysicalUserRangeWith(&model, SharedCopyWalkModel.virtual + @as(usize, LARGE_2M_PAGE_SIZE) - 16, SharedCopyWalkModel.physical + PAGE_SIZE - 16, output.len, true, 0)) |alias|
            @memcpy(@as([*]u8, @ptrFromInt(alias))[0..output.len], &output);
        try std.testing.expectEqualSlices(u8, &untouched, &model.backing);
        try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0xC4)), &output);
        try std.testing.expectEqual(limit - 2, model.publications);
        try std.testing.expectEqual(baseline.allocated + @as(u32, @intCast(limit)), model.frames.stats().allocated);
        retireOwnedHierarchy(&model, model.root(), model.root_physical);
        try std.testing.expectEqual(@as(u32, 0), model.frames.stats().allocated);
        try std.testing.expectEqual(baseline.free + baseline.allocated, model.frames.stats().free);
    }
}

test "user range retirement batches invalidation before private frames are reused" {
    const Model = struct {
        entries: [3]PageTableEntry,
        invalidations: usize = 0,
        releases: usize = 0,
        released_frames: u32 = 0,
        ordering_valid: bool = true,

        fn lookup(self: *@This(), address: usize) ?*PageTableEntry {
            return switch (address) {
                0x200000...0x3FFFFF => &self.entries[0],
                0x400000...0x400FFF => &self.entries[1],
                0x401000...0x401FFF => &self.entries[2],
                else => null,
            };
        }

        fn invalidate(self: *@This()) void {
            for (self.entries) |entry| {
                if (entryPresent(entry)) self.ordering_valid = false;
            }
            if (self.releases != 0) self.ordering_valid = false;
            self.invalidations += 1;
        }

        fn release(self: *@This(), _: frame_allocator.PhysicalAddress, count: u32) void {
            if (self.invalidations != 1) self.ordering_valid = false;
            self.releases += 1;
            self.released_frames += count;
        }
    };
    const flags = ENTRY_PRESENT | ENTRY_USER | ENTRY_WRITABLE | table64.NO_EXECUTE;
    var model = Model{ .entries = .{
        tableEntry(0x400000, flags | ENTRY_LARGE_PAGE, PAGE_OWNER_USER_PRIVATE),
        tableEntry(0x9000, flags, PAGE_OWNER_USER_PRIVATE),
        tableEntry(0xA000, flags, PAGE_OWNER_BORROWED),
    } };
    const before = model;
    try std.testing.expectError(error.InvalidRange, retireUserRange(&model, 0x201000, 0x200000));
    try std.testing.expectEqualDeep(before, model);
    model.entries[2] &= ~ENTRY_USER;
    const with_kernel_collision = model;
    try std.testing.expectError(error.KernelMappingCollision, retireUserRange(&model, 0x200000, 0x202000));
    try std.testing.expectEqualDeep(with_kernel_collision, model);
    model = before;
    try retireUserRange(&model, 0x200000, 0x202000);
    try std.testing.expect(model.ordering_valid);
    try std.testing.expectEqual(@as(usize, 1), model.invalidations);
    try std.testing.expectEqual(@as(usize, 2), model.releases);
    try std.testing.expectEqual(@as(u32, 513), model.released_frames);
    try std.testing.expectEqual(@as([3]PageTableEntry, @splat(0)), model.entries);
    try retireUserRange(&model, 0x200000, 0x202000);
    try std.testing.expectEqual(@as(usize, 1), model.invalidations);
    try std.testing.expectEqual(@as(usize, 2), model.releases);
}
