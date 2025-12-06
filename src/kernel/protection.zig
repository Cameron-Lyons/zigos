const std = @import("std");
const paging = @import("paging.zig");
const vga = @import("vga.zig");
const memory = @import("memory.zig");

pub const KERNEL_BASE = 0xC0000000;
pub const USER_SPACE_END = 0xC0000000;
pub const USER_STACK_TOP = 0xBFFFF000;
pub const USER_HEAP_START = 0x40000000;

pub const PROT_READ = 0x1;
pub const PROT_WRITE = 0x2;
pub const PROT_EXEC = 0x4;
pub const PROT_USER = 0x8;

pub fn verifyUserPointer(ptr: usize, size: usize) bool {
    if (ptr > 0xFFFFFFFF - size) {
        return false;
    }

    if (ptr >= USER_SPACE_END or ptr + size > USER_SPACE_END) {
        return false;
    }

    var addr = ptr & ~@as(usize, 0xFFF);
    const end_addr = (ptr + size + 0xFFF) & ~@as(usize, 0xFFF);

    while (addr < end_addr) : (addr += 0x1000) {
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

    const user_ptr = @as([*]const u8, @ptrFromInt(user_src));
    @memcpy(kernel_dest, user_ptr[0..kernel_dest.len]);
}

pub fn copyToUser(user_dest: usize, kernel_src: []const u8) !void {
    if (!verifyUserPointer(user_dest, kernel_src.len)) {
        return error.InvalidUserPointer;
    }

    const flags = disableInterrupts();
    defer restoreInterrupts(flags);

    const user_ptr = @as([*]u8, @ptrFromInt(user_dest));
    @memcpy(user_ptr[0..kernel_src.len], kernel_src);
}

pub fn copyStringFromUser(buffer: []u8, user_str: usize) ![]u8 {
    if (!verifyUserPointer(user_str, 1)) {
        return error.InvalidUserPointer;
    }

    var i: usize = 0;
    while (i < buffer.len) : (i += 1) {
        if (!verifyUserPointer(user_str + i, 1)) {
            return error.InvalidUserPointer;
        }

        const byte = @as(*const u8, @ptrFromInt(user_str + i)).*;
        buffer[i] = byte;

        if (byte == 0) {
            return buffer[0..i];
        }
    }

    return error.StringTooLong;
}

pub fn allocateUserMemory(size: usize, prot: u32) !usize {
    const page_count = (size + 0xFFF) / 0x1000;

    var virt_addr: u32 = USER_HEAP_START;
    while (virt_addr + (page_count * 0x1000) < USER_SPACE_END) : (virt_addr += 0x1000) {
        var found = true;
        var i: u32 = 0;
        while (i < page_count) : (i += 1) {
            if (paging.get_physical_address(virt_addr + i * 0x1000) != null) {
                found = false;
                break;
            }
        }

        if (found) {
            i = 0;
            while (i < page_count) : (i += 1) {
                const phys_page = memory.allocatePhysicalPage() orelse {
                    var j: u32 = 0;
                    while (j < i) : (j += 1) {
                        paging.unmap_page(virt_addr + j * 0x1000);
                    }
                    return error.OutOfMemory;
                };

                var flags = paging.PAGE_PRESENT | paging.PAGE_USER;
                if (prot & PROT_WRITE != 0) {
                    flags |= paging.PAGE_WRITABLE;
                }

                paging.mapPage(virt_addr + i * 0x1000, phys_page, flags);
            }

            return virt_addr;
        }
    }

    return error.OutOfVirtualMemory;
}

pub fn freeUserMemory(addr: usize, size: usize) void {
    const page_count = (size + 0xFFF) / 0x1000;
    var i: u32 = 0;
    while (i < page_count) : (i += 1) {
        paging.unmap_page(@intCast(addr + i * 0x1000));
    }
}

fn disableInterrupts() u32 {
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

