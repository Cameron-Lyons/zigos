const abi = @import("../process/syscall/abi.zig");
const process_mod = @import("../process/process.zig");
const vfs = @import("../fs/vfs.zig");
const vga = @import("../drivers/vga.zig");
const memory = @import("memory.zig");
const paging = @import("paging.zig");
const protection = @import("protection.zig");

const PAGE_SIZE: usize = 0x1000;
const PAGE_MASK: usize = PAGE_SIZE - 1;
const MAP_REGION_START: usize = 0x60000000;
const MAP_REGION_END: usize = 0x7FF00000;

pub const MMapError = error{
    InvalidArgument,
    NoMemory,
    AccessDenied,
    InvalidFd,
    NotMapped,
    TooManyMappings,
};

pub fn init() void {
    vga.print("Memory mapping support initialized\n");
}

fn alignDown(value: usize) usize {
    return value & ~PAGE_MASK;
}

fn alignUp(value: usize) usize {
    return (value + PAGE_MASK) & ~PAGE_MASK;
}

fn mappingEnd(mapping: *const process_mod.MemoryMapping) usize {
    return mapping.start_addr + mapping.length;
}

fn overlaps(start_a: usize, len_a: usize, start_b: usize, len_b: usize) bool {
    return start_a < start_b + len_b and start_b < start_a + len_a;
}

fn fileBytesForRange(mapping: *const process_mod.MemoryMapping, start: usize, length: usize) usize {
    const delta = start - mapping.start_addr;
    if (delta >= mapping.file_bytes) return 0;
    return @min(length, mapping.file_bytes - delta);
}

fn setMappingRange(
    target: *process_mod.MemoryMapping,
    source: *const process_mod.MemoryMapping,
    start: usize,
    length: usize,
    prot: u32,
) void {
    const delta = start - source.start_addr;
    target.* = .{
        .in_use = true,
        .start_addr = start,
        .length = length,
        .prot = prot,
        .flags = source.flags,
        .open_flags = source.open_flags,
        .vnode = source.vnode,
        .file_offset = source.file_offset + delta,
        .file_bytes = fileBytesForRange(source, start, length),
    };
}

fn findFreeMappingSlot(proc: *process_mod.Process) ?*process_mod.MemoryMapping {
    for (&proc.memory_mappings) |*mapping| {
        if (!mapping.in_use) return mapping;
    }
    return null;
}

fn retainMappingVnode(mapping: *const process_mod.MemoryMapping) void {
    if (mapping.vnode) |vnode| {
        vnode.ref_count += 1;
    }
}

fn releaseMappingVnode(mapping: *process_mod.MemoryMapping) void {
    if (mapping.vnode) |vnode| {
        if (vnode.ref_count > 0) {
            vnode.ref_count -= 1;
        }
    }
}

fn pageFlagsFromProt(prot: u32) u32 {
    var flags = paging.PAGE_PRESENT | paging.PAGE_USER;
    if ((prot & abi.PROT_WRITE) != 0) {
        flags |= paging.PAGE_WRITABLE;
    }
    return flags;
}

fn enterAddressSpace(proc: *process_mod.Process) *paging.PageDirectory {
    const page_directory = proc.page_directory;
    const old_page_directory = paging.getCurrentPageDirectory();
    if (page_directory) |pd| {
        if (old_page_directory != pd) {
            paging.switchPageDirectory(pd);
        }
    }
    return old_page_directory;
}

fn leaveAddressSpace(proc: *process_mod.Process, old_page_directory: *paging.PageDirectory) void {
    if (proc.page_directory) |page_directory| {
        if (old_page_directory != page_directory) {
            paging.switchPageDirectory(old_page_directory);
        }
    }
}

fn isRegionFree(start: usize, length: usize) bool {
    var addr = start;
    while (addr < start + length) : (addr += PAGE_SIZE) {
        if (paging.get_physical_address(@intCast(addr)) != null) {
            return false;
        }
    }
    return true;
}

fn findFreeRegion(proc: *process_mod.Process, hint: usize, length: usize) MMapError!usize {
    const start = if (hint >= MAP_REGION_START) alignDown(hint) else MAP_REGION_START;
    if (length > MAP_REGION_END - MAP_REGION_START) return error.NoMemory;

    const old_page_directory = enterAddressSpace(proc);
    defer leaveAddressSpace(proc, old_page_directory);

    var addr = start;
    while (addr + length <= MAP_REGION_END) : (addr += PAGE_SIZE) {
        if (isRegionFree(addr, length)) {
            return addr;
        }
    }

    if (start != MAP_REGION_START) {
        addr = MAP_REGION_START;
        while (addr + length <= start) : (addr += PAGE_SIZE) {
            if (isRegionFree(addr, length)) {
                return addr;
            }
        }
    }

    return error.NoMemory;
}

fn mapPages(base_addr: usize, length: usize, prot: u32) MMapError!void {
    const page_flags = pageFlagsFromProt(prot);
    var addr = base_addr;
    while (addr < base_addr + length) : (addr += PAGE_SIZE) {
        const phys_page = memory.allocatePhysicalPage() orelse return error.NoMemory;
        paging.mapPage(@intCast(addr), phys_page, page_flags);
        const page_ptr: [*]u8 = @ptrFromInt(addr);
        @memset(page_ptr[0..PAGE_SIZE], 0);
    }
}

fn unmapPages(base_addr: usize, length: usize) void {
    var addr = base_addr;
    while (addr < base_addr + length) : (addr += PAGE_SIZE) {
        paging.unmap_page(@intCast(addr));
    }
}

fn updatePageProtection(base_addr: usize, length: usize, prot: u32) void {
    const page_flags = pageFlagsFromProt(prot);
    var addr = base_addr;
    while (addr < base_addr + length) : (addr += PAGE_SIZE) {
        paging.set_current_page_flags(@intCast(addr), page_flags);
    }
}

fn loadFileMapping(vnode: *vfs.VNode, base_addr: usize, file_offset: u64, file_bytes: usize) MMapError!void {
    if (file_bytes == 0) return;
    const mapped: [*]u8 = @ptrFromInt(base_addr);
    _ = vfs.readVNode(vnode, mapped[0..file_bytes], file_offset) catch return error.InvalidFd;
}

fn writeBackRange(mapping: *const process_mod.MemoryMapping, start: usize, length: usize) MMapError!void {
    const vnode = mapping.vnode orelse return;
    if ((mapping.flags & abi.MAP_SHARED) == 0) return;

    const write_bytes = fileBytesForRange(mapping, start, length);
    if (write_bytes == 0) return;

    const delta = start - mapping.start_addr;
    const mapped: [*]u8 = @ptrFromInt(start);
    _ = vfs.writeVNode(vnode, mapped[0..write_bytes], mapping.file_offset + delta) catch return error.InvalidFd;
}

fn clearMapping(mapping: *process_mod.MemoryMapping) void {
    releaseMappingVnode(mapping);
    mapping.* = .{};
}

pub fn mmap(
    proc: *process_mod.Process,
    addr: usize,
    length: usize,
    prot: u32,
    flags: u32,
    vnode: ?*vfs.VNode,
    open_flags: u32,
    file_offset: u64,
    file_bytes: usize,
) MMapError!usize {
    if (length == 0) return error.InvalidArgument;
    if ((flags & abi.MAP_SHARED) != 0 and (flags & abi.MAP_PRIVATE) != 0) return error.InvalidArgument;
    if ((flags & abi.MAP_SHARED) == 0 and (flags & abi.MAP_PRIVATE) == 0) return error.InvalidArgument;

    const page_length = alignUp(length);
    const requested_addr = if (addr == 0) @as(usize, 0) else alignDown(addr);
    const base_addr = if ((flags & abi.MAP_FIXED) != 0) blk: {
        if ((addr & PAGE_MASK) != 0) return error.InvalidArgument;
        if (requested_addr < protection.USER_PROGRAM_START or requested_addr + page_length > protection.USER_SPACE_END) {
            return error.InvalidArgument;
        }
        break :blk requested_addr;
    } else try findFreeRegion(proc, requested_addr, page_length);

    if ((flags & abi.MAP_FIXED) != 0) {
        munmap(proc, base_addr, page_length) catch |err| switch (err) {
            error.NotMapped => {},
            else => return err,
        };
    }

    const old_page_directory = enterAddressSpace(proc);
    defer leaveAddressSpace(proc, old_page_directory);

    mapPages(base_addr, page_length, prot) catch |err| {
        return err;
    };
    errdefer unmapPages(base_addr, page_length);

    if (vnode) |node| {
        loadFileMapping(node, base_addr, file_offset, file_bytes) catch |err| return err;
    }

    const mapping = findFreeMappingSlot(proc) orelse return error.TooManyMappings;
    mapping.* = .{
        .in_use = true,
        .start_addr = base_addr,
        .length = page_length,
        .prot = prot,
        .flags = flags,
        .open_flags = open_flags,
        .vnode = vnode,
        .file_offset = file_offset,
        .file_bytes = file_bytes,
    };
    retainMappingVnode(mapping);
    return base_addr;
}

pub fn munmap(proc: *process_mod.Process, addr: usize, length: usize) MMapError!void {
    if (length == 0 or (addr & PAGE_MASK) != 0) return error.InvalidArgument;

    const page_length = alignUp(length);
    const range_end = addr + page_length;
    const old_page_directory = enterAddressSpace(proc);
    defer leaveAddressSpace(proc, old_page_directory);

    var unmapped_any = false;

    for (&proc.memory_mappings) |*mapping| {
        if (!mapping.in_use or !overlaps(addr, page_length, mapping.start_addr, mapping.length)) {
            continue;
        }

        const overlap_start = @max(addr, mapping.start_addr);
        const overlap_end = @min(range_end, mappingEnd(mapping));
        const overlap_length = overlap_end - overlap_start;
        const original = mapping.*;

        if (overlap_start == original.start_addr and overlap_end == mappingEnd(&original)) {
            writeBackRange(&original, overlap_start, overlap_length) catch return error.InvalidFd;
            unmapPages(overlap_start, overlap_length);
            clearMapping(mapping);
            unmapped_any = true;
            continue;
        }

        if (overlap_start == original.start_addr) {
            writeBackRange(&original, overlap_start, overlap_length) catch return error.InvalidFd;
            unmapPages(overlap_start, overlap_length);
            setMappingRange(mapping, &original, overlap_end, mappingEnd(&original) - overlap_end, original.prot);
            unmapped_any = true;
            continue;
        }

        if (overlap_end == mappingEnd(&original)) {
            writeBackRange(&original, overlap_start, overlap_length) catch return error.InvalidFd;
            unmapPages(overlap_start, overlap_length);
            setMappingRange(mapping, &original, original.start_addr, overlap_start - original.start_addr, original.prot);
            unmapped_any = true;
            continue;
        }

        const right_mapping = findFreeMappingSlot(proc) orelse return error.TooManyMappings;
        setMappingRange(right_mapping, &original, overlap_end, mappingEnd(&original) - overlap_end, original.prot);
        retainMappingVnode(right_mapping);

        writeBackRange(&original, overlap_start, overlap_length) catch {
            clearMapping(right_mapping);
            return error.InvalidFd;
        };
        unmapPages(overlap_start, overlap_length);
        setMappingRange(mapping, &original, original.start_addr, overlap_start - original.start_addr, original.prot);
        unmapped_any = true;
    }

    if (!unmapped_any) {
        return error.NotMapped;
    }
}

pub fn mprotect(proc: *process_mod.Process, addr: usize, length: usize, prot: u32) MMapError!void {
    if (length == 0 or (addr & PAGE_MASK) != 0) return error.InvalidArgument;

    const page_length = alignUp(length);
    const range_end = addr + page_length;
    const old_page_directory = enterAddressSpace(proc);
    defer leaveAddressSpace(proc, old_page_directory);

    var changed_any = false;

    for (&proc.memory_mappings) |*mapping| {
        if (!mapping.in_use or !overlaps(addr, page_length, mapping.start_addr, mapping.length)) {
            continue;
        }

        const overlap_start = @max(addr, mapping.start_addr);
        const overlap_end = @min(range_end, mappingEnd(mapping));
        const original = mapping.*;

        if (overlap_start == original.start_addr and overlap_end == mappingEnd(&original)) {
            mapping.prot = prot;
            updatePageProtection(mapping.start_addr, mapping.length, prot);
            changed_any = true;
            continue;
        }

        const left_len = overlap_start - original.start_addr;
        const middle_len = overlap_end - overlap_start;
        const right_len = mappingEnd(&original) - overlap_end;

        var left_mapping: ?*process_mod.MemoryMapping = null;
        var right_mapping: ?*process_mod.MemoryMapping = null;

        if (left_len > 0) {
            left_mapping = findFreeMappingSlot(proc) orelse return error.TooManyMappings;
        }
        if (right_len > 0) {
            right_mapping = findFreeMappingSlot(proc) orelse return error.TooManyMappings;
            if (left_mapping != null and right_mapping == left_mapping) {
                right_mapping = null;
                for (&proc.memory_mappings) |*candidate| {
                    if (!candidate.in_use and candidate != left_mapping.?) {
                        right_mapping = candidate;
                        break;
                    }
                }
                if (right_mapping == null) return error.TooManyMappings;
            }
        }

        if (left_mapping) |left| {
            setMappingRange(left, &original, original.start_addr, left_len, original.prot);
            retainMappingVnode(left);
        }
        if (right_mapping) |right| {
            setMappingRange(right, &original, overlap_end, right_len, original.prot);
            retainMappingVnode(right);
        }

        setMappingRange(mapping, &original, overlap_start, middle_len, prot);
        updatePageProtection(mapping.start_addr, mapping.length, prot);
        changed_any = true;
    }

    if (!changed_any) {
        return error.NotMapped;
    }
}

pub fn cloneMappings(parent: *const process_mod.Process, child: *process_mod.Process) void {
    child.memory_mappings = parent.memory_mappings;
    for (&child.memory_mappings) |*mapping| {
        if (mapping.in_use) {
            retainMappingVnode(mapping);
        }
    }
}

pub fn releaseProcessMappings(proc: *process_mod.Process) void {
    const old_page_directory = enterAddressSpace(proc);
    defer leaveAddressSpace(proc, old_page_directory);

    for (&proc.memory_mappings) |*mapping| {
        if (!mapping.in_use) continue;
        writeBackRange(mapping, mapping.start_addr, mapping.length) catch {};
        unmapPages(mapping.start_addr, mapping.length);
        clearMapping(mapping);
    }
}
