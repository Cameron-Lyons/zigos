const paging = @import("paging.zig");
const vga = @import("../drivers/vga.zig");
const memory = @import("memory.zig");

pub const KERNEL_BASE = 0xC0000000;
pub const USER_PROGRAM_START = 0x08000000;
pub const USER_SPACE_END = 0xC0000000;
pub const USER_STACK_TOP = 0xBFFFF000;
pub const USER_STARTUP_PAGE = USER_STACK_TOP;
pub const USER_HEAP_START = 0x40000000;

pub const PROT_READ = 0x1;
pub const PROT_WRITE = 0x2;
pub const PROT_EXEC = 0x4;
pub const PROT_USER = 0x8;

const PAGE_SIZE: usize = 0x1000;
const PAGE_MASK: usize = PAGE_SIZE - 1;

pub fn verifyUserPointer(ptr: usize, size: usize) bool {
    if (ptr > 0xFFFFFFFF - size) {
        return false;
    }

    if (ptr >= USER_SPACE_END or ptr + size > USER_SPACE_END) {
        return false;
    }

    var addr = ptr & ~PAGE_MASK;
    const end_addr = (ptr + size + PAGE_MASK) & ~PAGE_MASK;

    while (addr < end_addr) : (addr += PAGE_SIZE) {
        if (paging.get_physical_address(@intCast(addr)) == null) {
            return false;
        }
    }

    return true;
}

pub fn copyFromUser(kernel_dest: []u8, user_src: usize) !void {
    if (!verifyUserPointer(user_src, kernel_dest.len)) {
        return error.InvalidUserPointer;
    }

    const flags = disableInterrupts();
    defer restoreInterrupts(flags);

    const user_ptr: [*]const u8 = @ptrFromInt(user_src);
    @memcpy(kernel_dest, user_ptr[0..kernel_dest.len]);
}

pub fn copyToUser(user_dest: usize, kernel_src: []const u8) !void {
    if (!verifyUserPointer(user_dest, kernel_src.len)) {
        return error.InvalidUserPointer;
    }

    const flags = disableInterrupts();
    defer restoreInterrupts(flags);

    const user_ptr: [*]u8 = @ptrFromInt(user_dest);
    @memcpy(user_ptr[0..kernel_src.len], kernel_src);
}

pub fn copyStringFromUser(buffer: []u8, user_str: usize) ![]u8 {
    if (!verifyUserPointer(user_str, 1)) {
        return error.InvalidUserPointer;
    }

    var current_addr = user_str;
    var next_page = (current_addr & ~PAGE_MASK) + PAGE_SIZE;
    var i: usize = 0;
    while (i < buffer.len) : ({
        i += 1;
        current_addr += 1;
    }) {
        if (current_addr >= next_page) {
            if (!verifyUserPointer(current_addr, 1)) {
                return error.InvalidUserPointer;
            }
            next_page = (current_addr & ~PAGE_MASK) + PAGE_SIZE;
        }

        const byte = @as(*const u8, @ptrFromInt(current_addr)).*;
        buffer[i] = byte;

        if (byte == 0) {
            return buffer[0..i];
        }
    }

    return error.StringTooLong;
}

pub fn allocateUserMemory(size: usize, prot: u32) !usize {
    if (size == 0 or size > USER_SPACE_END - USER_HEAP_START) return error.OutOfVirtualMemory;
    const page_count = (size + PAGE_MASK) / PAGE_SIZE;

    var virt_addr: u32 = USER_HEAP_START;
    while (virt_addr + (page_count * PAGE_SIZE) < USER_SPACE_END) : (virt_addr += PAGE_SIZE) {
        var found = true;
        var i: u32 = 0;
        while (i < page_count) : (i += 1) {
            if (paging.get_physical_address(virt_addr + i * PAGE_SIZE) != null) {
                found = false;
                break;
            }
        }

        if (found) {
            i = 0;
            while (i < page_count) : (i += 1) {
                const phys_page = paging.alloc_frames(1) orelse {
                    var j: u32 = 0;
                    while (j < i) : (j += 1) {
                        paging.unmap_page(virt_addr + j * PAGE_SIZE);
                    }
                    return error.OutOfMemory;
                };

                var flags = paging.PAGE_PRESENT | paging.PAGE_USER;
                if (prot & PROT_WRITE != 0) {
                    flags |= paging.PAGE_WRITABLE;
                }

                paging.mapPage(virt_addr + i * PAGE_SIZE, phys_page, flags);
            }

            return virt_addr;
        }
    }

    return error.OutOfVirtualMemory;
}

pub fn freeUserMemory(addr: usize, size: usize) void {
    const page_count = (size + PAGE_MASK) / PAGE_SIZE;
    var i: u32 = 0;
    while (i < page_count) : (i += 1) {
        paging.unmap_page(@intCast(addr + i * PAGE_SIZE));
    }
}

fn disableInterrupts() u32 {
    // SAFETY: populated by the subsequent inline assembly reading EFLAGS
    var flags: u32 = undefined;
    asm volatile (
        \\pushfl
        \\popl %[flags]
        \\cli
        : [flags] "=r" (flags),
    );
    return flags;
}

fn restoreInterrupts(flags: u32) void {
    asm volatile (
        \\pushl %[flags]
        \\popfl
        :
        : [flags] "r" (flags),
    );
}

pub fn protectKernelMemory() void {
    var addr: u32 = KERNEL_BASE;
    while (addr < 0xFFFFFFFF) : (addr += 0x1000) {
        if (paging.get_physical_address(addr)) |phys| {
            paging.mapPage(addr, phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
        }

        if (addr == 0xFFFFF000) break;
    }

    vga.print("Kernel memory protected\n");
}
