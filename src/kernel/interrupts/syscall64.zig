const x86 = @import("../../arch/x86.zig");
const smp = @import("../smp.zig");

pub const FRED_ONLY_TRAPS = @import("../../arch/cpu_baseline.zig").FRED_ONLY_TRAPS;

const CpuState = extern struct {
    kernel_stack_top: usize = 0,
    user_stack_pointer: usize = 0,
    cpu_index: usize = 0,
    kernel_port: usize = 0,
    active_task_id: u64 = 0,
};

extern var stack_top: u8;

pub export var zigos_syscall_cpu_states: [smp.MAX_CPUS]CpuState align(64) = [_]CpuState{.{}} ** smp.MAX_CPUS;
pub const zigos_syscall_cpu_state = &zigos_syscall_cpu_states[0];

pub fn init() void {
    bindCpu(0, @intFromPtr(&stack_top));
    x86.enableFred(zigos_syscall_cpu_states[0].kernel_stack_top);
    if (!enabled()) unreachable;
}

pub fn initApplicationProcessor(cpu_index: u8, stack_top_value: usize) void {
    bindCpu(cpu_index, stack_top_value);
    x86.enableFred(stack_top_value);
    if (!x86.fredEnabled()) unreachable;
}

pub fn setKernelStack(stack_top_value: usize) void {
    const state = currentState();
    const stack_slot: *volatile usize = &state.kernel_stack_top;
    stack_slot.* = stack_top_value;
    x86.setFredRsp0(stack_top_value);
}

pub fn currentCpuIndex() u8 {
    return @truncate(currentState().cpu_index);
}

pub fn enabled() bool {
    return x86.fredEnabled();
}

pub fn setKernelPort(port_addr: usize) void {
    currentState().kernel_port = port_addr;
}

pub fn clearKernelPort() void {
    currentState().kernel_port = 0;
}

pub fn currentKernelPortAddr() usize {
    return currentState().kernel_port;
}

pub fn setActiveTaskId(task_id: u64) void {
    currentState().active_task_id = task_id;
}

pub fn currentActiveTaskId() u64 {
    return currentState().active_task_id;
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
        @offsetOf(CpuState, "cpu_index") != 16 or
        @offsetOf(CpuState, "kernel_port") != 24 or
        @offsetOf(CpuState, "active_task_id") != 32)
    {
        @compileError("x86-64 FRED CPU state layout diverged from GS-relative fields");
    }
    if (!FRED_ONLY_TRAPS) {
        @compileError("syscall configuration must remain FRED-only");
    }
}
