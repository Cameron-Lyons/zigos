const x86 = @import("../../arch/x86.zig");
const gdt = @import("gdt64.zig");

const CpuState = extern struct {
    kernel_stack_top: usize = 0,
    user_stack_pointer: usize = 0,
};

const USER_STAR_BASE_SELECTOR: u16 = gdt.USER_DATA_SEG - 8;
const SYSCALL_STAR_VALUE = (@as(u64, gdt.KERNEL_CODE_SEG) << 32) |
    (@as(u64, USER_STAR_BASE_SELECTOR) << 48);
const RFLAGS_TRAP: u64 = 1 << 8;
const RFLAGS_INTERRUPT: u64 = 1 << 9;
const RFLAGS_DIRECTION: u64 = 1 << 10;
const RFLAGS_IOPL: u64 = 3 << 12;
const RFLAGS_NESTED_TASK: u64 = 1 << 14;
const RFLAGS_ALIGNMENT_CHECK: u64 = 1 << 18;
const SYSCALL_RFLAGS_MASK = RFLAGS_TRAP |
    RFLAGS_INTERRUPT |
    RFLAGS_DIRECTION |
    RFLAGS_IOPL |
    RFLAGS_NESTED_TASK |
    RFLAGS_ALIGNMENT_CHECK;

extern fn zigos_syscall_entry() callconv(.c) void;

pub export var zigos_syscall_cpu_state: CpuState align(16) = .{};

pub fn init() void {
    zigos_syscall_cpu_state = .{};
    x86.writeMsr(x86.IA32_GS_BASE_MSR, 0);
    x86.writeMsr(x86.IA32_KERNEL_GS_BASE_MSR, @intFromPtr(&zigos_syscall_cpu_state));
    x86.writeMsr(x86.IA32_STAR_MSR, SYSCALL_STAR_VALUE);
    x86.writeMsr(x86.IA32_LSTAR_MSR, @intFromPtr(&zigos_syscall_entry));
    x86.writeMsr(x86.IA32_FMASK_MSR, SYSCALL_RFLAGS_MASK);
    x86.writeMsr(x86.EFER_MSR, x86.readMsr(x86.EFER_MSR) | x86.EFER_SCE);
    if (!enabled()) unreachable;
}

pub fn setKernelStack(stack_top: usize) void {
    if (stack_top == 0 or (stack_top & 0xF) != 0) unreachable;
    const stack_slot: *volatile usize = &zigos_syscall_cpu_state.kernel_stack_top;
    stack_slot.* = stack_top;
}

pub fn enabled() bool {
    return x86.syscallExtensionEnabled() and
        x86.readMsr(x86.IA32_KERNEL_GS_BASE_MSR) == @intFromPtr(&zigos_syscall_cpu_state) and
        x86.readMsr(x86.IA32_LSTAR_MSR) == @intFromPtr(&zigos_syscall_entry) and
        x86.readMsr(x86.IA32_FMASK_MSR) == SYSCALL_RFLAGS_MASK;
}

comptime {
    if (@offsetOf(CpuState, "kernel_stack_top") != 0 or
        @offsetOf(CpuState, "user_stack_pointer") != 8 or
        @sizeOf(CpuState) != 16)
    {
        @compileError("x86-64 syscall CPU state diverged from syscall64.S");
    }
    if (gdt.USER_DATA_SEG + 8 != gdt.USER_CODE_SEG) {
        @compileError("SYSRET requires the user data descriptor immediately before user code");
    }
    if (SYSCALL_STAR_VALUE != 0x0010_0008_0000_0000) {
        @compileError("x86-64 syscall selectors diverged from the STAR encoding");
    }
}
