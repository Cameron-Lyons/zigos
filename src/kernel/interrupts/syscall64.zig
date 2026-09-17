const x86 = @import("../../arch/x86.zig");
const gdt = @import("gdt64.zig");
const smp = @import("../smp.zig");

pub const FRED_ONLY_TRAPS = @import("../../arch/cpu_baseline.zig").FRED_ONLY_TRAPS;

const CpuState = extern struct {
    kernel_stack_top: usize = 0,
    user_stack_pointer: usize = 0,
    cpu_index: usize = 0,
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
extern var stack_top: u8;

pub export var zigos_syscall_cpu_states: [smp.MAX_CPUS]CpuState align(64) = [_]CpuState{.{}} ** smp.MAX_CPUS;
pub const zigos_syscall_cpu_state = &zigos_syscall_cpu_states[0];

pub fn init() void {
    bindCpu(0, @intFromPtr(&stack_top));
    const features = @import("../../arch/cpu_features.zig").detect();
    if (features.fred and features.lkgs) {
        x86.enableFred(zigos_syscall_cpu_states[0].kernel_stack_top);
        if (!enabled()) unreachable;
        return;
    }
    x86.writeMsr(x86.IA32_STAR_MSR, SYSCALL_STAR_VALUE);
    x86.writeMsr(x86.IA32_LSTAR_MSR, @intFromPtr(&zigos_syscall_entry));
    x86.writeMsr(x86.IA32_FMASK_MSR, SYSCALL_RFLAGS_MASK);
    x86.writeMsr(x86.EFER_MSR, x86.readMsr(x86.EFER_MSR) | x86.EFER_SCE);
    if (!enabled()) unreachable;
}

pub fn initApplicationProcessor(cpu_index: u8, stack_top_value: usize) void {
    bindCpu(cpu_index, stack_top_value);
    const features = @import("../../arch/cpu_features.zig").detect();
    if (features.fred and features.lkgs) {
        x86.enableFred(stack_top_value);
    }
}

pub fn setKernelStack(stack_top_value: usize) void {
    const state = currentState();
    const stack_slot: *volatile usize = &state.kernel_stack_top;
    stack_slot.* = stack_top_value;
    if (x86.fredEnabled()) {
        x86.setFredRsp0(stack_top_value);
    }
}

pub fn currentCpuIndex() u8 {
    return @truncate(currentState().cpu_index);
}

pub fn enabled() bool {
    if (x86.fredEnabled()) return true;
    return x86.syscallExtensionEnabled() and
        x86.readMsr(x86.IA32_LSTAR_MSR) == @intFromPtr(&zigos_syscall_entry) and
        x86.readMsr(x86.IA32_FMASK_MSR) == SYSCALL_RFLAGS_MASK;
}

fn bindCpu(cpu_index: u8, stack_top_value: usize) void {
    if (stack_top_value == 0 or (stack_top_value & 0xF) != 0) unreachable;
    if (cpu_index >= smp.MAX_CPUS) unreachable;
    zigos_syscall_cpu_states[cpu_index] = .{
        .kernel_stack_top = stack_top_value,
        .cpu_index = cpu_index,
    };
    const state_addr = @intFromPtr(&zigos_syscall_cpu_states[cpu_index]);
    x86.writeMsr(x86.IA32_GS_BASE_MSR, state_addr);
    x86.writeMsr(x86.IA32_KERNEL_GS_BASE_MSR, state_addr);
}

fn currentState() *CpuState {
    const addr = x86.readMsr(x86.IA32_GS_BASE_MSR);
    if (addr == 0) return &zigos_syscall_cpu_states[0];
    return @ptrFromInt(addr);
}

comptime {
    if (@offsetOf(CpuState, "kernel_stack_top") != 0 or
        @offsetOf(CpuState, "user_stack_pointer") != 8 or
        @offsetOf(CpuState, "cpu_index") != 16)
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
