const builtin = @import("builtin");
const std = @import("std");
const implementation = if (builtin.cpu.arch == .x86_64)
    @import("paging64.zig")
else
    @import("paging.zig");

pub const PAGE_PRESENT = implementation.PAGE_PRESENT;
pub const PAGE_WRITABLE = implementation.PAGE_WRITABLE;
pub const PAGE_USER = implementation.PAGE_USER;
pub const PAGE_WRITE_THROUGH = implementation.PAGE_WRITE_THROUGH;
pub const PAGE_CACHE_DISABLE = implementation.PAGE_CACHE_DISABLE;
pub const PAGE_ACCESSED = implementation.PAGE_ACCESSED;
pub const PAGE_DIRTY = implementation.PAGE_DIRTY;
pub const PAGE_GLOBAL = implementation.PAGE_GLOBAL;

pub const PageTableEntry = implementation.PageTableEntry;
pub const PageTable = implementation.PageTable;
pub const PageDirectory = implementation.PageDirectory;
pub const FrameRun = implementation.FrameRun;
pub const FrameStats = implementation.FrameStats;
pub const FrameReleaseError = implementation.FrameReleaseError;
pub const UserAddressSpace = implementation.UserAddressSpace;
pub const UserPermissions = implementation.UserPermissions;
pub const UserMapError = implementation.UserMapError;
pub const UserWriteError = implementation.UserWriteError;
pub const UserAddressSpaceDestroyError = implementation.UserAddressSpaceDestroyError;

pub const alloc_frames = implementation.alloc_frames;
pub const release_frames = implementation.release_frames;
pub const frameStats = implementation.frameStats;
pub const enableWriteProtect = implementation.enableWriteProtect;
pub const createUserAddressSpace = implementation.createUserAddressSpace;
pub const mapOwnedUserRange = implementation.mapOwnedUserRange;
pub const writeOwnedUserRange = implementation.writeOwnedUserRange;
pub const destroyUserAddressSpace = implementation.destroyUserAddressSpace;
pub const switchToUserAddressSpace = implementation.switchToUserAddressSpace;
pub const init = implementation.init;
pub const page_fault_handler = implementation.page_fault_handler;
pub const getCurrentPageDirectory = implementation.getCurrentPageDirectory;
pub const switchPageDirectory = implementation.switchPageDirectory;

pub fn mapKernelBorrowedPage(virt_addr: usize, phys_addr: usize, flags: u32) void {
    if (comptime builtin.cpu.arch == .x86_64) {
        implementation.mapKernelBorrowedPage(virt_addr, phys_addr, flags);
    } else {
        implementation.mapKernelBorrowedPage(
            narrowAddress(virt_addr, "kernel virtual mapping exceeds the 32-bit pager"),
            narrowAddress(phys_addr, "kernel physical mapping exceeds the 32-bit pager"),
            flags,
        );
    }
}

pub fn setPageReadOnly(virt_addr: usize) void {
    if (comptime builtin.cpu.arch == .x86_64) {
        implementation.setPageReadOnly(virt_addr);
    } else {
        implementation.setPageReadOnly(narrowAddress(virt_addr, "read-only mapping exceeds the 32-bit pager"));
    }
}

pub fn unmapBorrowedCurrentPage(virt_addr: usize) bool {
    if (comptime builtin.cpu.arch == .x86_64) {
        return implementation.unmapBorrowedCurrentPage(virt_addr);
    }
    return implementation.unmapBorrowedCurrentPage(
        narrowAddress(virt_addr, "unmapped address exceeds the 32-bit pager"),
    );
}

fn narrowAddress(address: usize, message: []const u8) u32 {
    return std.math.cast(u32, address) orelse @panic(message);
}
