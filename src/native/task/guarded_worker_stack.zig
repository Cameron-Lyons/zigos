//! Fixed-capacity native stacks with an inaccessible page at either end. The
//! exclusive owner frees a stack only after its cooperative worker completes.
const std = @import("std");
const builtin = @import("builtin");
const freestanding = builtin.os.tag == .freestanding;
pub const STACK_BYTES = 128 * 1024;
pub const MAX_STACKS = 4;
const PAGE_BYTES = 4096;
const STRIDE = STACK_BYTES + 2 * PAGE_BYTES;
const paging = if (freestanding) @import("../../kernel/memory/paging64.zig") else struct {};
const Allocation = if (freestanding) paging.FrameRun else []align(std.heap.page_size_min) u8;
var occupied: [MAX_STACKS]bool = @splat(false);

pub const Stack = struct {
    bytes: []align(16) u8,
    allocation: Allocation,
    slot: usize = 0,

    pub fn allocate() !Stack {
        if (!freestanding) {
            const page = std.heap.pageSize();
            if (STACK_BYTES % page != 0) return error.UnsupportedPageSize;
            const mapping = try std.posix.mmap(null, STACK_BYTES + 2 * page, .{}, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
            errdefer std.posix.munmap(mapping);
            const bytes = mapping[page..][0..STACK_BYTES];
            if (std.posix.errno(std.posix.system.mprotect(bytes.ptr, bytes.len, .{ .READ = true, .WRITE = true })) != .SUCCESS)
                return error.StackProtectionFailed;
            @memset(bytes, 0);
            return .{ .bytes = @alignCast(bytes), .allocation = mapping };
        }
        try requireContext();
        const layout = @import("../../kernel/memory/virtual_layout.zig");
        const slot = std.mem.indexOfScalar(bool, &occupied, false) orelse return error.WorkerStackLimit;
        const base = layout.native_stacks.base + slot * STRIDE;
        for (0..STRIDE / PAGE_BYTES) |page| {
            if (paging.currentPagePermissions(base + page * PAGE_BYTES) != null) return error.WorkerStackCollision;
        }
        const run = paging.allocGeneralFrames(STACK_BYTES / PAGE_BYTES) orelse return error.OutOfMemory;
        errdefer paging.releaseGeneralFrames(run) catch @panic("worker stack frame accounting");
        var mapped: usize = 0;
        errdefer for (0..mapped) |page| {
            if (!paging.unmapBorrowedCurrentPage(base + PAGE_BYTES + page * PAGE_BYTES)) @panic("worker stack unmap failed");
        };
        for (0..STACK_BYTES / PAGE_BYTES) |page| {
            try paging.tryMapKernelBorrowedPage(base + PAGE_BYTES + page * PAGE_BYTES, @intCast(run.base + page * PAGE_BYTES), paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
            mapped += 1;
        }
        occupied[slot] = true;
        const bytes: []align(16) u8 = @as([*]align(16) u8, @ptrFromInt(base + PAGE_BYTES))[0..STACK_BYTES];
        @memset(bytes, 0);
        return .{ .bytes = bytes, .allocation = run, .slot = slot };
    }

    pub fn deinit(self: *Stack) void {
        if (self.bytes.len == 0) return;
        requireContext() catch @panic("worker stack released outside its owner context");
        std.crypto.secureZero(u8, self.bytes);
        if (freestanding) {
            for (0..STACK_BYTES / PAGE_BYTES) |page| {
                if (!paging.unmapBorrowedCurrentPage(@intFromPtr(self.bytes.ptr) + page * PAGE_BYTES)) @panic("worker stack unmap failed");
            }
            paging.releaseGeneralFrames(self.allocation) catch @panic("worker stack frame accounting");
            occupied[self.slot] = false;
        } else std.posix.munmap(self.allocation);
        self.bytes = &.{};
    }

    pub fn guardsPresent(self: *const Stack) bool {
        if (!freestanding) return self.bytes.len == STACK_BYTES;
        const base = @intFromPtr(self.bytes.ptr);
        if (self.bytes.len != STACK_BYTES or paging.currentPagePermissions(base - PAGE_BYTES) != null or
            paging.currentPagePermissions(base + STACK_BYTES) != null) return false;
        for (0..STACK_BYTES / PAGE_BYTES) |page| {
            const permissions = paging.currentPagePermissions(base + page * PAGE_BYTES) orelse return false;
            if (permissions.user or permissions.executable or !permissions.writable) return false;
        }
        return true;
    }
};

fn requireContext() !void {
    if (freestanding) {
        if (@import("../../kernel/smp.zig").currentCpuIndex() != 0) return error.WrongCpu;
        if (@import("../../kernel/interrupts/context.zig").active()) return error.InterruptContext;
        if (!paging.kernelAddressSpaceActive()) return error.UserAddressSpaceActive;
    }
}

comptime {
    if (freestanding and MAX_STACKS * STRIDE > @import("../../kernel/memory/virtual_layout.zig").native_stacks.bytes)
        @compileError("worker stacks exceed their virtual window");
}

test "cooperative worker stack allocates bounded storage and erases before reuse" {
    var stack = try Stack.allocate();
    defer stack.deinit();
    try std.testing.expectEqual(@as(usize, STACK_BYTES), stack.bytes.len);
    try std.testing.expect(stack.guardsPresent());
    try std.testing.expect(std.mem.allEqual(u8, stack.bytes, 0));
    @memset(stack.bytes, 0xa5);
    stack.deinit();
    try std.testing.expectEqual(@as(usize, 0), stack.bytes.len);
    stack = try Stack.allocate();
    try std.testing.expect(std.mem.allEqual(u8, stack.bytes, 0));
}
