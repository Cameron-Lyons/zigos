const builtin = @import("builtin");
const std = @import("std");
const implementation = if (builtin.cpu.arch == .x86_64)
    @import("gdt64.zig")
else
    @import("gdt.zig");

pub const GdtPtr = implementation.GdtPtr;
pub const Tss = implementation.Tss;
pub const KERNEL_CODE_SEG = implementation.KERNEL_CODE_SEG;
pub const KERNEL_DATA_SEG = implementation.KERNEL_DATA_SEG;
pub const USER_CODE_SEG = implementation.USER_CODE_SEG;
pub const USER_DATA_SEG = implementation.USER_DATA_SEG;
pub const TSS_SEG = implementation.TSS_SEG;
pub const DOUBLE_FAULT_IST_INDEX = if (builtin.cpu.arch == .x86_64)
    implementation.DOUBLE_FAULT_IST_INDEX
else
    @as(u3, 0);
pub const DOUBLE_FAULT_TSS_SEG = if (builtin.cpu.arch == .x86_64)
    implementation.TSS_SEG
else
    implementation.DOUBLE_FAULT_TSS_SEG;
pub const InterruptedContext = implementation.InterruptedContext;

pub const init = implementation.init;
pub const refreshDoubleFaultCr3 = implementation.refreshDoubleFaultCr3;
pub const interruptedContext = implementation.interruptedContext;

pub fn configureDoubleFaultTask(handler_address: u32) void {
    if (comptime builtin.cpu.arch == .x86_64) {
        implementation.configureDoubleFaultIst();
    } else {
        implementation.configureDoubleFaultTask(handler_address);
    }
}

pub fn setKernelStack(stack: usize) void {
    if (comptime builtin.cpu.arch == .x86_64) {
        implementation.setKernelStack(stack);
    } else {
        implementation.setKernelStack(std.math.cast(u32, stack) orelse
            @panic("kernel trap stack exceeds the 32-bit TSS"));
    }
}

pub fn configureDoubleFaultIst() void {
    if (comptime builtin.cpu.arch == .x86_64) {
        implementation.configureDoubleFaultIst();
    }
}
