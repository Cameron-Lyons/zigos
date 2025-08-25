const std = @import("std");
const vfs = @import("vfs.zig");
const paging = @import("paging.zig");
const memory = @import("memory.zig");
const process = @import("process.zig");
const vga = @import("vga.zig");

pub const MMapFlags = struct {
    pub const SHARED = 0x01;
    pub const PRIVATE = 0x02;
    pub const ANONYMOUS = 0x20;
    pub const FIXED = 0x10;
    pub const GROWSDOWN = 0x100;
    pub const LOCKED = 0x2000;
    pub const NORESERVE = 0x4000;
    pub const POPULATE = 0x8000;
    pub const NONBLOCK = 0x10000;
};

pub const MMapProt = struct {
    pub const NONE = 0x0;
    pub const READ = 0x1;
    pub const WRITE = 0x2;
    pub const EXEC = 0x4;
    pub const GROWSDOWN = 0x01000000;
    pub const GROWSUP = 0x02000000;
};

pub const MMapError = error{
    InvalidArgument,
    NoMemory,
    AccessDenied,
    InvalidFd,
    Overflow,
    NoDevice,
    InvalidLength,
    ExceedsLimit,
    Locked,
    TooManyMappings,
};

pub const MemoryMapping = struct {
    start_addr: usize,
    length: usize,
    prot: u32,
    flags: u32,
    fd: ?i32,
    offset: u64,
    vnode: ?*vfs.VNode,
    next: ?*MemoryMapping,
    prev: ?*MemoryMapping,
};

const MAX_MAPPINGS = 256;
var memory_mappings: [MAX_MAPPINGS]?MemoryMapping = [_]?MemoryMapping{null} ** MAX_MAPPINGS;
var mapping_list: ?*MemoryMapping = null;

pub fn init() void {
    for (&memory_mappings) |*mapping| {
        mapping.* = null;
    }
    mapping_list = null;
    vga.print("Memory mapping support initialized\n");
}

pub fn mmap(addr: ?usize, length: usize, prot: u32, flags: u32, fd: i32, offset: u64) MMapError!usize {
    if (length == 0) {
        return MMapError.InvalidLength;
    }

    if ((flags & MMapFlags.PRIVATE) != 0 and (flags & MMapFlags.SHARED) != 0) {
        return MMapError.InvalidArgument;
    }

    if ((flags & MMapFlags.PRIVATE) == 0 and (flags & MMapFlags.SHARED) == 0) {
        return MMapError.InvalidArgument;
    }

    const page_aligned_length = ((length + 0xFFF) / 0x1000) * 0x1000;

    var vnode: ?*vfs.VNode = null;
    if ((flags & MMapFlags.ANONYMOUS) == 0) {
        if (fd < 0) {
            return MMapError.InvalidFd;
        }
        
        const file_ops = @import("file_ops.zig");
        const index = @as(usize, @intCast(fd));
        if (index >= file_ops.MAX_FDS) {
            return MMapError.InvalidFd;
        }
        
        if (file_ops.file_descriptors[index]) |file_desc| {
            vnode = file_desc.vnode;
            
            if ((prot & MMapProt.WRITE) != 0 and (flags & MMapFlags.SHARED) != 0) {
                if ((file_desc.flags & 0x01) == 0) {
                    return MMapError.AccessDenied;
                }
            }
        } else {
            return MMapError.InvalidFd;
        }
    }

    var base_addr: usize = undefined;
    if (addr) |requested_addr| {
        if ((flags & MMapFlags.FIXED) != 0) {
            base_addr = requested_addr & ~@as(usize, 0xFFF);
            
            var current = mapping_list;
            while (current) |mapping| : (current = mapping.next) {
                if (overlaps(base_addr, page_aligned_length, mapping.start_addr, mapping.length)) {
                    munmap(mapping.start_addr, mapping.length) catch {};
                }
            }
        } else {
            base_addr = findFreeRegion(requested_addr, page_aligned_length) orelse 
                       return MMapError.NoMemory;
        }
    } else {
        base_addr = findFreeRegion(0x400000, page_aligned_length) orelse 
                   return MMapError.NoMemory;
    }

    const num_pages = page_aligned_length / 0x1000;
    var i: usize = 0;
    while (i < num_pages) : (i += 1) {
        const virt_addr = base_addr + (i * 0x1000);
        const phys_page = memory.allocatePhysicalPage() orelse return MMapError.NoMemory;
        
        var page_flags = paging.PAGE_PRESENT | paging.PAGE_USER;
        if ((prot & MMapProt.WRITE) != 0) {
            page_flags |= paging.PAGE_WRITABLE;
        }
        if ((prot & MMapProt.EXEC) == 0) {
            page_flags |= paging.PAGE_NO_EXECUTE;
        }
        
        paging.mapPage(virt_addr, phys_page, page_flags) catch return MMapError.NoMemory;
    }

    if ((flags & MMapFlags.ANONYMOUS) == 0 and vnode != null) {
        const read_size = @min(page_aligned_length, vnode.?.size -| offset);
        if (read_size > 0) {
            const buffer = @as([*]u8, @ptrFromInt(base_addr))[0..read_size];
            _ = vnode.?.ops.read(vnode.?, buffer, offset) catch |err| {
                unmapPages(base_addr, num_pages);
                return switch (err) {
                    else => MMapError.NoDevice,
                };
            };
        }
    }

    if ((flags & MMapFlags.ANONYMOUS) != 0 or 
        ((flags & MMapFlags.ANONYMOUS) == 0 and vnode != null and 
         vnode.?.size -| offset < page_aligned_length)) {
        const clear_start = if ((flags & MMapFlags.ANONYMOUS) != 0) 
            0 
        else 
            vnode.?.size -| offset;
        const clear_size = page_aligned_length - clear_start;
        if (clear_size > 0) {
            const clear_buffer = @as([*]u8, @ptrFromInt(base_addr + clear_start))[0..clear_size];
            @memset(clear_buffer, 0);
        }
    }

    var mapping_index: usize = 0;
    while (mapping_index < MAX_MAPPINGS) : (mapping_index += 1) {
        if (memory_mappings[mapping_index] == null) {
            memory_mappings[mapping_index] = MemoryMapping{
                .start_addr = base_addr,
                .length = page_aligned_length,
                .prot = prot,
                .flags = flags,
                .fd = if ((flags & MMapFlags.ANONYMOUS) != 0) null else fd,
                .offset = offset,
                .vnode = vnode,
                .next = mapping_list,
                .prev = null,
            };
            
            if (mapping_list) |first| {
                first.prev = &memory_mappings[mapping_index].?;
            }
            mapping_list = &memory_mappings[mapping_index].?;
            
            return base_addr;
        }
    }

    unmapPages(base_addr, num_pages);
    return MMapError.TooManyMappings;
}

pub fn munmap(addr: usize, length: usize) MMapError!void {
    if (length == 0) {
        return MMapError.InvalidLength;
    }

    const page_aligned_addr = addr & ~@as(usize, 0xFFF);
    const page_aligned_length = ((length + (addr - page_aligned_addr) + 0xFFF) / 0x1000) * 0x1000;

    var current = mapping_list;
    while (current) |mapping| {
        const next = mapping.next;
        
        if (mapping.start_addr >= page_aligned_addr and 
            mapping.start_addr < page_aligned_addr + page_aligned_length) {
            
            if ((mapping.flags & MMapFlags.SHARED) != 0 and 
                (mapping.prot & MMapProt.WRITE) != 0 and 
                mapping.vnode != null) {
                msync(mapping.start_addr, mapping.length, 1) catch {};
            }
            
            const num_pages = mapping.length / 0x1000;
            unmapPages(mapping.start_addr, num_pages);
            
            if (mapping.prev) |prev| {
                prev.next = mapping.next;
            } else {
                mapping_list = mapping.next;
            }
            if (mapping.next) |next_mapping| {
                next_mapping.prev = mapping.prev;
            }
            
            for (&memory_mappings, 0..) |*maybe_mapping, i| {
                if (maybe_mapping.* != null and &maybe_mapping.*.? == mapping) {
                    memory_mappings[i] = null;
                    break;
                }
            }
        }
        
        current = next;
    }
}

pub fn mprotect(addr: usize, length: usize, prot: u32) MMapError!void {
    if (length == 0) {
        return MMapError.InvalidLength;
    }

    const page_aligned_addr = addr & ~@as(usize, 0xFFF);
    const page_aligned_length = ((length + (addr - page_aligned_addr) + 0xFFF) / 0x1000) * 0x1000;

    var current = mapping_list;
    while (current) |mapping| : (current = mapping.next) {
        if (overlaps(page_aligned_addr, page_aligned_length, mapping.start_addr, mapping.length)) {
            mapping.prot = prot;
            
            const num_pages = mapping.length / 0x1000;
            var i: usize = 0;
            while (i < num_pages) : (i += 1) {
                const virt_addr = mapping.start_addr + (i * 0x1000);
                
                var page_flags = paging.PAGE_PRESENT | paging.PAGE_USER;
                if ((prot & MMapProt.WRITE) != 0) {
                    page_flags |= paging.PAGE_WRITABLE;
                }
                if ((prot & MMapProt.EXEC) == 0) {
                    page_flags |= paging.PAGE_NO_EXECUTE;
                }
                
                paging.updatePageFlags(virt_addr, page_flags) catch return MMapError.NoMemory;
            }
        }
    }
}

pub fn msync(addr: usize, length: usize, flags: u32) MMapError!void {
    _ = flags;
    
    if (length == 0) {
        return MMapError.InvalidLength;
    }

    const page_aligned_addr = addr & ~@as(usize, 0xFFF);
    const page_aligned_length = ((length + (addr - page_aligned_addr) + 0xFFF) / 0x1000) * 0x1000;

    var current = mapping_list;
    while (current) |mapping| : (current = mapping.next) {
        if (overlaps(page_aligned_addr, page_aligned_length, mapping.start_addr, mapping.length)) {
            if (mapping.vnode) |vnode| {
                if ((mapping.flags & MMapFlags.SHARED) != 0 and 
                    (mapping.prot & MMapProt.WRITE) != 0) {
                    const buffer = @as([*]u8, @ptrFromInt(mapping.start_addr))[0..mapping.length];
                    _ = vnode.ops.write(vnode, buffer, mapping.offset) catch |err| {
                        return switch (err) {
                            else => MMapError.NoDevice,
                        };
                    };
                }
            }
        }
    }
}

pub fn madvise(addr: usize, length: usize, advice: u32) MMapError!void {
    _ = advice;
    
    if (length == 0) {
        return MMapError.InvalidLength;
    }

    const page_aligned_addr = addr & ~@as(usize, 0xFFF);
    const page_aligned_length = ((length + (addr - page_aligned_addr) + 0xFFF) / 0x1000) * 0x1000;

    var current = mapping_list;
    while (current) |mapping| : (current = mapping.next) {
        if (overlaps(page_aligned_addr, page_aligned_length, mapping.start_addr, mapping.length)) {
            return;
        }
    }
    
    return MMapError.InvalidArgument;
}

fn findFreeRegion(hint: usize, size: usize) ?usize {
    var addr = if (hint > 0) hint & ~@as(usize, 0xFFF) else 0x400000;
    const max_addr = 0x80000000;
    
    while (addr + size <= max_addr) : (addr += 0x1000) {
        var found_overlap = false;
        var current = mapping_list;
        while (current) |mapping| : (current = mapping.next) {
            if (overlaps(addr, size, mapping.start_addr, mapping.length)) {
                found_overlap = true;
                addr = mapping.start_addr + mapping.length;
                break;
            }
        }
        
        if (!found_overlap) {
            return addr;
        }
    }
    
    return null;
}

fn overlaps(addr1: usize, len1: usize, addr2: usize, len2: usize) bool {
    return addr1 < addr2 + len2 and addr2 < addr1 + len1;
}

fn unmapPages(addr: usize, num_pages: usize) void {
    var i: usize = 0;
    while (i < num_pages) : (i += 1) {
        const virt_addr = addr + (i * 0x1000);
        paging.unmapPage(virt_addr) catch {};
    }
}

pub fn handlePageFault(fault_addr: usize, error_code: u32) bool {
    const page_aligned_addr = fault_addr & ~@as(usize, 0xFFF);
    
    var current = mapping_list;
    while (current) |mapping| : (current = mapping.next) {
        if (fault_addr >= mapping.start_addr and 
            fault_addr < mapping.start_addr + mapping.length) {
            
            if ((error_code & 0x01) == 0) {
                const phys_page = memory.allocatePhysicalPage() orelse return false;
                
                var page_flags = paging.PAGE_PRESENT | paging.PAGE_USER;
                if ((mapping.prot & MMapProt.WRITE) != 0) {
                    page_flags |= paging.PAGE_WRITABLE;
                }
                if ((mapping.prot & MMapProt.EXEC) == 0) {
                    page_flags |= paging.PAGE_NO_EXECUTE;
                }
                
                paging.mapPage(page_aligned_addr, phys_page, page_flags) catch return false;
                
                if (mapping.vnode) |vnode| {
                    const page_offset = page_aligned_addr - mapping.start_addr;
                    const file_offset = mapping.offset + page_offset;
                    
                    if (file_offset < vnode.size) {
                        const read_size = @min(0x1000, vnode.size - file_offset);
                        const buffer = @as([*]u8, @ptrFromInt(page_aligned_addr))[0..read_size];
                        _ = vnode.ops.read(vnode, buffer, file_offset) catch {};
                        
                        if (read_size < 0x1000) {
                            const clear_buffer = @as([*]u8, @ptrFromInt(page_aligned_addr + read_size))[0..(0x1000 - read_size)];
                            @memset(clear_buffer, 0);
                        }
                    }
                } else {
                    const buffer = @as([*]u8, @ptrFromInt(page_aligned_addr))[0..0x1000];
                    @memset(buffer, 0);
                }
                
                return true;
            }
            
            if ((error_code & 0x02) != 0 and (mapping.prot & MMapProt.WRITE) == 0) {
                return false;
            }
            
            if ((mapping.flags & MMapFlags.PRIVATE) != 0 and (error_code & 0x02) != 0) {
                const phys_page = memory.allocatePhysicalPage() orelse return false;
                const old_buffer = @as([*]u8, @ptrFromInt(page_aligned_addr))[0..0x1000];
                const new_buffer = @as([*]u8, @ptrFromInt(phys_page))[0..0x1000];
                @memcpy(new_buffer, old_buffer);
                
                var page_flags = paging.PAGE_PRESENT | paging.PAGE_USER | paging.PAGE_WRITABLE;
                if ((mapping.prot & MMapProt.EXEC) == 0) {
                    page_flags |= paging.PAGE_NO_EXECUTE;
                }
                
                paging.mapPage(page_aligned_addr, phys_page, page_flags) catch return false;
                return true;
            }
        }
    }
    
    return false;
}