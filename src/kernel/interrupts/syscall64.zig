const x86 = @import("../../arch/x86.zig");
const gdt = @import("gdt64.zig");
const cpu_identity = @import("../cpu_identity.zig");
const native_entry = @import("../../arch/x86_64/native_entry_state.zig");

pub const FRED_ONLY_TRAPS = @import("../../arch/cpu_baseline.zig").FRED_ONLY_TRAPS;

const ENTRY_PKU = native_entry.ENTRY_PKU;
const ENTRY_FRED = native_entry.ENTRY_FRED;
const ENTRY_READY = native_entry.ENTRY_READY;

const USER_STAR_BASE_SELECTOR: u16 = (gdt.USER_DATA_SEG - 8) | 3;
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
const IA32_APIC_BASE_MSR: u32 = 0x1B;
const APIC_BASE_BSP: u64 = 1 << 8;

extern fn zigos_syscall_entry() callconv(.c) void;
extern var stack_top: u8;

pub fn init() void {
    const interrupts_enabled = x86.interruptsEnabled();
    x86.cli();
    // Firmware owns TSC_AUX until authenticated BSP setup. Do not select a
    // software owner slot using that inherited value before publishing CPU0.
    if (!bootstrapIdentityWith(Hardware{})) haltInvalidStack();
    bindCpu(0, @intFromPtr(&stack_top));
    enableNativeEntry(@intFromPtr(&stack_top));
    if (!setKernelStack(@intFromPtr(&stack_top)) or !enabled()) haltInvalidStack();
    publishNativeEntryModes(0);
    if (interrupts_enabled) x86.sti();
}

pub fn initApplicationProcessor(cpu_index: u8, stack_top_value: usize) void {
    const interrupts_enabled = x86.interruptsEnabled();
    x86.cli();
    bindCpu(cpu_index, stack_top_value);
    enableNativeEntry(stack_top_value);
    if (!setKernelStack(stack_top_value) or !enabled()) haltInvalidStack();
    publishNativeEntryModes(cpu_index);
    if (interrupts_enabled) x86.sti();
}

pub fn setKernelStack(stack_top_value: usize) bool {
    return switch (installKernelStack(stack_top_value, Hardware{})) {
        .bound => true,
        .rejected => false,
        .failed => haltInvalidStack(),
    };
}

pub fn enabled() bool {
    return enabledWith(Hardware{});
}

const StackBinding = enum { bound, rejected, failed };

inline fn bootstrapIdentityWith(hardware: anytype) bool {
    if (!hardware.supportsRdpid() or (hardware.readMsr(IA32_APIC_BASE_MSR) & APIC_BASE_BSP) == 0) return false;
    hardware.initializeLogicalCpu(0);
    return true;
}

// This is a cold owner transaction. No native entry mode or GS stack is
// published until the loaded TSS and every hardware stack readback agree.
inline fn installKernelStack(stack_top_value: usize, hardware: anytype) StackBinding {
    const interrupts_enabled = hardware.interruptsEnabled();
    hardware.disableInterrupts();
    var restore_interrupts = true;
    defer if (restore_interrupts and interrupts_enabled) hardware.enableInterrupts();
    const state = native_entry.current();
    const cr4 = hardware.readCr4();
    if (!x86.validFredStackTop(stack_top_value) or
        !gdt.kernelStackOwnerIsLoaded(hardware.readGdt(), hardware.readTaskRegister()) or
        hardware.readMsr(x86.IA32_GS_BASE_MSR) != @intFromPtr(state) or
        state.userspace_xstate != 0 or state.kernel_xstate != 0 or
        state.resume_rsp != 0 or state.resume_rip != 0 or state.resume_requested != 0 or
        (publishedFredMode(state) != null and state.native_entry_modes != entryModesFromCr4(cr4)))
        return .rejected;
    const fred = (cr4 & x86.CR4_FRED) != 0;
    const emergency_top = gdt.doubleFaultStackTop();
    if (!x86.validFredStackTop(emergency_top) or
        (fred and !x86.fredControlMatchesWith(emergency_top, hardware.fredEntryAddress(), hardware)))
        return .rejected;

    const previous_modes = state.native_entry_modes;
    state.native_entry_modes = previous_modes & ~ENTRY_READY;
    hardware.setTssKernelStack(stack_top_value);
    if (fred) hardware.updateFredStack(stack_top_value);
    if (!gdt.kernelStackOwnerIsLoaded(hardware.readGdt(), hardware.readTaskRegister()) or
        !hardware.kernelStackMatches(stack_top_value) or hardware.readCr4() != cr4 or
        hardware.readMsr(x86.IA32_GS_BASE_MSR) != @intFromPtr(state) or
        (fred and !x86.fredEnabledWith(stack_top_value, emergency_top, hardware.fredEntryAddress(), hardware)))
    {
        state.native_entry_modes &= ~ENTRY_READY;
        restore_interrupts = false;
        return .failed;
    }
    // A failed hardware update cannot publish a mixed GS/TSS/FRED binding.
    state.kernel_stack_top = stack_top_value;
    state.native_entry_modes = previous_modes;
    return .bound;
}

inline fn enabledWith(hardware: anytype) bool {
    if ((hardware.readCr4() & x86.CR4_FRED) != 0) {
        return x86.fredEnabledWith(native_entry.current().kernel_stack_top, gdt.doubleFaultStackTop(), hardware.fredEntryAddress(), hardware) and
            selectorsEnabledWith(hardware);
    }
    return selectorsEnabledWith(hardware) and
        hardware.readMsr(x86.IA32_LSTAR_MSR) == hardware.syscallEntryAddress() and
        hardware.readMsr(x86.IA32_FMASK_MSR) == SYSCALL_RFLAGS_MASK;
}

inline fn selectorsEnabledWith(hardware: anytype) bool {
    return (hardware.readMsr(x86.EFER_MSR) & x86.EFER_SCE) != 0 and
        hardware.readMsr(x86.IA32_STAR_MSR) == SYSCALL_STAR_VALUE;
}

inline fn haltInvalidStack() noreturn {
    x86.cli();
    while (true) x86.hlt();
}

const Hardware = struct {
    pub inline fn supportsRdpid(_: @This()) bool {
        return @import("../../arch/cpu_features.zig").detect().rdpid;
    }
    pub inline fn initializeLogicalCpu(_: @This(), index: u8) void {
        cpu_identity.initialize(index);
    }
    pub inline fn interruptsEnabled(_: @This()) bool {
        return x86.interruptsEnabled();
    }
    pub inline fn disableInterrupts(_: @This()) void {
        x86.cli();
    }
    pub inline fn enableInterrupts(_: @This()) void {
        x86.sti();
    }
    pub inline fn readCr4(_: @This()) usize {
        return x86.readCr4();
    }
    pub inline fn readMsr(_: @This(), msr: u32) u64 {
        return x86.readMsr(msr);
    }
    pub inline fn fredEntryAddress(_: @This()) usize {
        return x86.fredEntryAddress();
    }
    pub inline fn syscallEntryAddress(_: @This()) usize {
        return @intFromPtr(&zigos_syscall_entry);
    }
    pub inline fn readGdt(_: @This()) gdt.GdtPtr {
        var gdtr: gdt.GdtPtr = undefined;
        asm volatile ("sgdt (%[table])"
            :
            : [table] "r" (&gdtr),
            : .{ .memory = true });
        return gdtr;
    }
    pub inline fn readTaskRegister(_: @This()) u16 {
        return asm volatile ("str %[selector]"
            : [selector] "=r" (-> u16),
        );
    }
    pub inline fn setTssKernelStack(_: @This(), top: usize) void {
        gdt.setKernelStack(top);
    }
    pub inline fn updateFredStack(_: @This(), top: usize) void {
        x86.updateFredStack(top);
    }
    pub inline fn kernelStackMatches(_: @This(), top: usize) bool {
        return gdt.kernelStackMatches(top);
    }
};

pub fn setKernelPort(port_addr: usize) void {
    native_entry.current().kernel_port = port_addr;
}

pub fn clearKernelPort() void {
    native_entry.current().kernel_port = 0;
}

pub fn currentKernelPortAddr() usize {
    return native_entry.current().kernel_port;
}

pub fn setActiveTaskId(task_id: u64) void {
    native_entry.current().active_task_id = task_id;
}

pub fn currentActiveTaskId() u64 {
    return native_entry.current().active_task_id;
}

fn enableNativeEntry(kernel_stack_top: usize) void {
    // FRED reads STAR directly on ring transitions and requires SCE for SYSCALL.
    x86.writeMsr(x86.IA32_STAR_MSR, SYSCALL_STAR_VALUE);
    x86.writeMsr(x86.EFER_MSR, x86.readMsr(x86.EFER_MSR) | x86.EFER_SCE);
    if (!syscallSelectorsEnabled()) haltInvalidStack();
    const features = @import("../../arch/cpu_features.zig").detect();
    if (features.fred and features.lkgs) {
        x86.enableFred(kernel_stack_top, gdt.doubleFaultStackTop());
        if (!x86.fredEnabled(kernel_stack_top, gdt.doubleFaultStackTop())) haltInvalidStack();
        return;
    }
    enableSyscallMsrs();
    if (!syscallMsrsEnabled()) haltInvalidStack();
}

fn enableSyscallMsrs() void {
    x86.writeMsr(x86.IA32_LSTAR_MSR, @intFromPtr(&zigos_syscall_entry));
    x86.writeMsr(x86.IA32_FMASK_MSR, SYSCALL_RFLAGS_MASK);
}

fn syscallMsrsEnabled() bool {
    return syscallSelectorsEnabled() and
        x86.readMsr(x86.IA32_LSTAR_MSR) == @intFromPtr(&zigos_syscall_entry) and
        x86.readMsr(x86.IA32_FMASK_MSR) == SYSCALL_RFLAGS_MASK;
}

fn syscallSelectorsEnabled() bool {
    return x86.syscallExtensionEnabled() and
        x86.readMsr(x86.IA32_STAR_MSR) == SYSCALL_STAR_VALUE;
}

fn bindCpu(cpu_index: u8, stack_top_value: usize) void {
    if (!x86.validFredStackTop(stack_top_value) or cpu_index >= cpu_identity.MAX_CPUS or
        cpu_identity.currentIndex() != cpu_index or
        !gdt.kernelStackOwnerIsLoaded((Hardware{}).readGdt(), (Hardware{}).readTaskRegister())) haltInvalidStack();
    const state = native_entry.current();
    if (state.native_entry_modes != 0 or state.userspace_xstate != 0 or state.kernel_xstate != 0 or
        state.resume_rsp != 0 or state.resume_rip != 0 or state.resume_requested != 0) haltInvalidStack();
    if (!@import("../../arch/cpu_features.zig").detect().rdpid) @panic("RDPID is required for native CPU identity");
    const state_addr = @intFromPtr(native_entry.initializeCpu(cpu_index, 0));
    x86.writeMsr(x86.IA32_GS_BASE_MSR, state_addr);
    // ERETU (or the explicit validation path's SWAPGS) installs the user base.
    x86.writeMsr(x86.IA32_KERNEL_GS_BASE_MSR, 0);
    cpu_identity.initialize(cpu_index);
}

inline fn publishNativeEntryModes(cpu_index: u8) void {
    // Prepared entry never clears TS or re-reads immutable CPU controls. Publish
    // only after this CPU's complete xstate and native-entry setup is verified.
    if (!x86.xsavesEnabled() or x86.taskSwitched()) haltInvalidStack();
    native_entry.stateForCpu(cpu_index).native_entry_modes = entryModesFromCr4(x86.readCr4());
}

inline fn entryModesFromCr4(cr4: usize) u8 {
    return ENTRY_READY |
        (if ((cr4 & x86.CR4_PKE) != 0) ENTRY_PKU else @as(u8, 0)) |
        (if ((cr4 & x86.CR4_FRED) != 0) ENTRY_FRED else @as(u8, 0));
}

inline fn publishedFredMode(state: *const volatile native_entry.State) ?bool {
    if ((state.native_entry_modes & ENTRY_READY) == 0) return null;
    return (state.native_entry_modes & ENTRY_FRED) != 0;
}

comptime {
    if (gdt.USER_DATA_SEG + 8 != gdt.USER_CODE_SEG) {
        @compileError("SYSRET requires the user data descriptor immediately before user code");
    }
    if (SYSCALL_STAR_VALUE != 0x0013_0008_0000_0000) {
        @compileError("x86-64 syscall selectors diverged from the STAR encoding");
    }
}

test "native entry modes remain bound to each initialized logical CPU" {
    const std = @import("std");
    const previous_index = cpu_identity.currentIndex();
    var previous_states: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (&previous_states, 0..) |*state, index| state.* = native_entry.stateForCpu(@intCast(index)).*;
    defer {
        for (&previous_states, 0..) |*state, index| native_entry.stateForCpu(@intCast(index)).* = state.*;
        cpu_identity.setIndexForTest(previous_index);
    }
    for (0..cpu_identity.MAX_CPUS) |index| {
        _ = native_entry.initializeCpu(@intCast(index), 0);
        cpu_identity.setIndexForTest(@intCast(index));
        try std.testing.expectEqual(@as(?bool, null), publishedFredMode(native_entry.current()));
        const cr4 = (if ((index & 1) != 0) x86.CR4_PKE else @as(usize, 0)) |
            (if ((index & 2) != 0) x86.CR4_FRED else @as(usize, 0));
        native_entry.current().native_entry_modes = entryModesFromCr4(cr4 | x86.CR4_SMEP | x86.CR4_OSXSAVE);
        native_entry.current().kernel_stack_top = 0xFFFF_8000_1000_0000 + index * 4096;
        setKernelPort(0xFFFF_8000_2000_0000 + index * 64);
        setActiveTaskId(100 + index);
    }
    // Interleave CPUs after publication: PKE or FRED on another CPU must not
    // change the prepared mode read from the selected CPU's GS state.
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2);
        cpu_identity.setIndexForTest(index);
        try std.testing.expectEqual(@as(?bool, (index & 2) != 0), publishedFredMode(native_entry.current()));
        try std.testing.expectEqual((index & 1) != 0, (native_entry.current().native_entry_modes & ENTRY_PKU) != 0);
        try std.testing.expectEqual(@as(u8, 0), native_entry.current().native_entry_modes & ~(ENTRY_READY | ENTRY_PKU | ENTRY_FRED));
        try std.testing.expectEqual(@as(usize, 0xFFFF_8000_1000_0000 + @as(usize, index) * 4096), native_entry.current().kernel_stack_top);
        try std.testing.expectEqual(@as(usize, 0xFFFF_8000_2000_0000 + @as(usize, index) * 64), currentKernelPortAddr());
        try std.testing.expectEqual(@as(u64, 100 + index), currentActiveTaskId());
        clearKernelPort();
        try std.testing.expectEqual(@as(usize, 0), currentKernelPortAddr());
    }
    // Task ownership survives every independently cleared per-CPU port slot.
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        try std.testing.expectEqual(@as(usize, 0), currentKernelPortAddr());
        try std.testing.expectEqual(@as(u64, 100 + index), currentActiveTaskId());
    }
}

const StackTestModel = struct {
    const std = @import("std");
    const Fault = enum { none, rsp0, rsp1, rsp2, rsp3, config, levels, tss, ist, cr4, gs };
    const Cpu = struct {
        interrupts: bool = true,
        cr4: usize = x86.CR4_FRED | x86.CR4_PKE,
        gdtr: gdt.GdtPtr = undefined,
        tr: u16 = gdt.TSS_SEG,
        gs: u64 = 0,
        rsp: [4]u64 = @splat(0),
        config: u64 = 0xFFFF_FFFF_8200_0000,
        levels: u64 = @as(u64, 3) << 16,
        writes: usize = 0,
        fred_reads: usize = 0,
        tss_writes: usize = 0,
        fault: Fault = .none,
        original_top: usize = 0,
    };
    cpus: [cpu_identity.MAX_CPUS]Cpu = @splat(.{}),

    fn selected(self: *@This()) *Cpu {
        return &self.cpus[cpu_identity.currentIndex()];
    }
    fn init(self: *@This()) void {
        for (&self.cpus, 0..) |*cpu, index| {
            const top = 0xFFFF_8000_1000_0000 + index * 4096;
            gdt.Testing.initialized(@intCast(index), true);
            gdt.Testing.tss(@intCast(index)).ist1 = 0xFFFF_8000_0200_0000 + (index + 1) * gdt.DOUBLE_FAULT_STACK_TOTAL_BYTES;
            cpu.* = .{ .gdtr = gdt.Testing.gdtr(@intCast(index)), .gs = @intFromPtr(native_entry.stateForCpu(@intCast(index))), .rsp = .{ top, top, top, gdt.Testing.tss(@intCast(index)).ist1 }, .original_top = top };
            gdt.Testing.tss(@intCast(index)).rsp0 = top;
            native_entry.stateForCpu(@intCast(index)).* = .{
                .kernel_stack_top = top,
                .kernel_port = 0xFFFF_8000_2000_0000 + index * 128,
                .active_task_id = 100 + index,
                .native_entry_modes = ENTRY_READY | ENTRY_PKU | ENTRY_FRED,
                .user_stack_pointer = 0x7000_0000 + index * 4096,
            };
        }
    }
    pub fn interruptsEnabled(self: *@This()) bool {
        return self.selected().interrupts;
    }
    pub fn disableInterrupts(self: *@This()) void {
        self.selected().interrupts = false;
    }
    pub fn enableInterrupts(self: *@This()) void {
        self.selected().interrupts = true;
    }
    pub fn readCr4(self: *@This()) usize {
        const cpu = self.selected();
        return cpu.cr4 ^ (if (cpu.tss_writes != 0 and cpu.fault == .cr4) x86.CR4_PKE else @as(usize, 0));
    }
    pub fn readGdt(self: *@This()) gdt.GdtPtr {
        return self.selected().gdtr;
    }
    pub fn readTaskRegister(self: *@This()) u16 {
        return self.selected().tr;
    }
    pub fn fredEntryAddress(_: *@This()) usize {
        return 0xFFFF_FFFF_8200_0000;
    }
    pub fn syscallEntryAddress(_: *@This()) usize {
        return 0xFFFF_FFFF_8200_1000;
    }
    pub fn readMsr(self: *@This(), msr: u32) u64 {
        const cpu = self.selected();
        if (msr >= x86.IA32_FRED_RSP0_MSR and msr <= x86.IA32_FRED_RSP3_MSR) {
            cpu.fred_reads += 1;
            const index = msr - x86.IA32_FRED_RSP0_MSR;
            return cpu.rsp[index] ^ (if (cpu.writes != 0 and cpu.fault == .rsp3 and index == 3) @as(u64, 64) else @as(u64, 0));
        }
        return switch (msr) {
            x86.IA32_GS_BASE_MSR => cpu.gs ^ (if (cpu.writes != 0 and cpu.fault == .gs) @as(u64, 128) else @as(u64, 0)),
            x86.IA32_FRED_CONFIG_MSR => blk: {
                cpu.fred_reads += 1;
                break :blk cpu.config ^ (if (cpu.writes != 0 and cpu.fault == .config) @as(u64, 4096) else @as(u64, 0));
            },
            x86.IA32_FRED_STKLVLS_MSR => blk: {
                cpu.fred_reads += 1;
                break :blk cpu.levels ^ (if (cpu.writes != 0 and cpu.fault == .levels) @as(u64, 1) else @as(u64, 0));
            },
            x86.EFER_MSR => x86.EFER_SCE,
            x86.IA32_STAR_MSR => SYSCALL_STAR_VALUE,
            x86.IA32_LSTAR_MSR => self.syscallEntryAddress(),
            x86.IA32_FMASK_MSR => SYSCALL_RFLAGS_MASK,
            else => unreachable,
        };
    }
    pub fn writeMsr(self: *@This(), msr: u32, value: u64) void {
        const cpu = self.selected();
        std.debug.assert(!cpu.interrupts);
        std.debug.assert(native_entry.current().kernel_stack_top == cpu.original_top);
        std.debug.assert((native_entry.current().native_entry_modes & ENTRY_READY) == 0);
        const index = msr - x86.IA32_FRED_RSP0_MSR;
        std.debug.assert(index < 3);
        const rejected = (index == 0 and cpu.fault == .rsp0) or (index == 1 and cpu.fault == .rsp1) or (index == 2 and cpu.fault == .rsp2);
        if (!rejected) cpu.rsp[index] = value;
        cpu.writes += 1;
    }
    pub fn updateFredStack(self: *@This(), top: usize) void {
        x86.updateFredStackWith(top, self);
    }
    pub fn setTssKernelStack(self: *@This(), top: usize) void {
        const cpu = self.selected();
        std.debug.assert(!cpu.interrupts);
        std.debug.assert(native_entry.current().kernel_stack_top == cpu.original_top);
        std.debug.assert((native_entry.current().native_entry_modes & ENTRY_READY) == 0);
        gdt.setKernelStack(top);
        if (cpu.fault == .tss) gdt.Testing.tss(cpu_identity.currentIndex()).rsp0 ^= 64;
        if (cpu.fault == .ist) gdt.Testing.tss(cpu_identity.currentIndex()).ist1 ^= 64;
        cpu.tss_writes += 1;
    }
    pub fn kernelStackMatches(_: *@This(), top: usize) bool {
        return gdt.kernelStackMatches(top);
    }
};

const StackTestFixture = struct {
    tables: gdt.Testing.Snapshot,
    index: u8,
    states: [cpu_identity.MAX_CPUS]native_entry.State,
    fn install() @This() {
        var previous = @This(){ .tables = gdt.Testing.install(), .index = cpu_identity.currentIndex(), .states = undefined };
        for (&previous.states, 0..) |*state, index| state.* = native_entry.stateForCpu(@intCast(index)).*;
        return previous;
    }
    fn restore(self: *const @This()) void {
        self.tables.restore();
        for (&self.states, 0..) |*state, index| native_entry.stateForCpu(@intCast(index)).* = state.*;
        cpu_identity.setIndexForTest(self.index);
    }
};

test "cold stack binding authenticates all sixteen loaded owners and publishes GS after exact readback" {
    const std = @import("std");
    const fixture = StackTestFixture.install();
    defer fixture.restore();
    var model = StackTestModel{};
    model.init();
    var expected: [cpu_identity.MAX_CPUS]native_entry.State = undefined;
    for (&expected, 0..) |*state, index| state.* = native_entry.stateForCpu(@intCast(index)).*;
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2);
        cpu_identity.setIndexForTest(index);
        const top = 0xFFFF_8000_3000_0000 + @as(usize, index) * 4096;
        model.cpus[index].interrupts = index % 2 == 0;
        const original_if = model.cpus[index].interrupts;
        try std.testing.expectEqual(StackBinding.bound, installKernelStack(top, &model));
        try std.testing.expectEqual(original_if, model.cpus[index].interrupts);
        try std.testing.expectEqual(@as(usize, 1), model.cpus[index].tss_writes);
        try std.testing.expectEqual(@as(usize, 3), model.cpus[index].writes);
        try std.testing.expect(gdt.kernelStackMatches(top));
        try std.testing.expect(enabledWith(&model));
        expected[index].kernel_stack_top = top;
        for (&expected, 0..) |*state, neighbor| {
            try std.testing.expectEqualDeep(state.*, native_entry.stateForCpu(@intCast(neighbor)).*);
            try std.testing.expectEqual(@as(u64, state.kernel_stack_top), gdt.Testing.tss(@intCast(neighbor)).rsp0);
        }
    }
}

test "cold stack binding rejects foreign unloaded active and malformed owners before writes" {
    const std = @import("std");
    const fixture = StackTestFixture.install();
    defer fixture.restore();
    var model = StackTestModel{};
    const Attack = enum { low, noncanonical, unaligned, gdtr, limit, tr, gs, unloaded, ist, userspace_xstate, kernel_xstate, resume_rsp, resume_rip, resume_requested, mode, config, levels, emergency };
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        inline for (@typeInfo(Attack).@"enum".field_values) |value| {
            model.init();
            gdt.Testing.initialized(@intCast(index), true);
            const attack: Attack = @fromBackingInt(@intCast(value));
            var top: usize = 0xFFFF_8000_3000_0000 + index * 4096;
            const cpu = &model.cpus[index];
            switch (attack) {
                .low => top = 0x1000,
                .noncanonical => top = 0xFFFF_0000_0000_0000,
                .unaligned => top += 8,
                .gdtr => cpu.gdtr = gdt.Testing.gdtr(@intCast((index + 1) % cpu_identity.MAX_CPUS)),
                .limit => cpu.gdtr.limit -= 1,
                .tr => cpu.tr |= 4,
                .gs => cpu.gs = @intFromPtr(native_entry.stateForCpu(@intCast((index + 1) % cpu_identity.MAX_CPUS))),
                .unloaded => gdt.Testing.initialized(@intCast(index), false),
                .ist => gdt.Testing.tss(@intCast(index)).ist1 ^= 64,
                .userspace_xstate => native_entry.current().userspace_xstate = 64,
                .kernel_xstate => native_entry.current().kernel_xstate = 64,
                .resume_rsp => native_entry.current().resume_rsp = 64,
                .resume_rip => native_entry.current().resume_rip = 64,
                .resume_requested => native_entry.current().resume_requested = 1,
                .mode => native_entry.current().native_entry_modes ^= ENTRY_FRED,
                .config => cpu.config ^= 4096,
                .levels => cpu.levels ^= 1,
                .emergency => cpu.rsp[3] ^= 64,
            }
            const before = native_entry.current().*;
            const tss_before = gdt.Testing.tss(@intCast(index)).*;
            cpu.interrupts = index % 2 == 0;
            const original_if = cpu.interrupts;
            try std.testing.expectEqual(StackBinding.rejected, installKernelStack(top, &model));
            try std.testing.expectEqual(original_if, cpu.interrupts);
            try std.testing.expectEqual(@as(usize, 0), cpu.writes + cpu.tss_writes);
            try std.testing.expectEqualDeep(before, native_entry.current().*);
            try std.testing.expectEqualDeep(tss_before, gdt.Testing.tss(@intCast(index)).*);
            gdt.Testing.tss(@intCast(index)).ist1 = cpu.rsp[3] ^ (if (attack == .emergency) @as(u64, 64) else @as(u64, 0));
        }
    }
}

test "cold stack binding readback failure keeps IF masked GS unpublished and readiness revoked" {
    const std = @import("std");
    const fixture = StackTestFixture.install();
    defer fixture.restore();
    var model = StackTestModel{};
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        inline for (@typeInfo(StackTestModel.Fault).@"enum".field_values[1..]) |value| {
            model.init();
            // Previous hostile IST cases must not affect the next transaction.
            gdt.Testing.tss(@intCast(index)).ist1 = 0xFFFF_8000_0200_0000 + (index + 1) * gdt.DOUBLE_FAULT_STACK_TOTAL_BYTES;
            model.cpus[index].rsp[3] = gdt.Testing.tss(@intCast(index)).ist1;
            model.cpus[index].fault = @fromBackingInt(@intCast(value));
            const before = native_entry.current().*;
            try std.testing.expectEqual(StackBinding.failed, installKernelStack(0xFFFF_8000_3000_0000 + index * 4096, &model));
            try std.testing.expect(!model.cpus[index].interrupts);
            try std.testing.expectEqual(before.kernel_stack_top, native_entry.current().kernel_stack_top);
            try std.testing.expectEqual(before.native_entry_modes & ~ENTRY_READY, native_entry.current().native_entry_modes);
            try std.testing.expectEqual(before.active_task_id, native_entry.current().active_task_id);
            for (0..cpu_identity.MAX_CPUS) |neighbor| {
                if (neighbor == index) continue;
                try std.testing.expectEqual(@as(usize, 0), model.cpus[neighbor].writes + model.cpus[neighbor].tss_writes);
                try std.testing.expectEqual(model.cpus[neighbor].original_top, native_entry.stateForCpu(@intCast(neighbor)).kernel_stack_top);
            }
        }
    }
}

test "cold legacy stack binding never accesses FRED MSRs and active malformed FRED cannot fall back" {
    const std = @import("std");
    const fixture = StackTestFixture.install();
    defer fixture.restore();
    var model = StackTestModel{};
    model.init();
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        const cpu = &model.cpus[index];
        cpu.cr4 &= ~x86.CR4_FRED;
        native_entry.current().native_entry_modes &= ~ENTRY_FRED;
        try std.testing.expectEqual(StackBinding.bound, installKernelStack(0xFFFF_8000_3000_0000 + index * 4096, &model));
        try std.testing.expect(enabledWith(&model));
        try std.testing.expectEqual(@as(usize, 0), cpu.writes + cpu.fred_reads);
        // Valid legacy STAR/LSTAR/FMASK remain in this model. Actual FRED must
        // reject its foreign stack instead of using those legacy values.
        cpu.cr4 |= x86.CR4_FRED;
        try std.testing.expect(!enabledWith(&model));
    }
}

test "cold FRED readiness rejects matching invalid expected stacks without MSR reads" {
    const std = @import("std");
    const fixture = StackTestFixture.install();
    defer fixture.restore();
    var model = StackTestModel{};
    model.init();
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        const cpu = &model.cpus[index];
        const valid_top = cpu.original_top;
        const valid_emergency = cpu.rsp[3];
        for ([_]usize{ 0, 0x1000, 0xFFFF_0000_0000_0000, valid_top + 8 }) |invalid| {
            cpu.rsp[0] = invalid;
            cpu.rsp[1] = invalid;
            cpu.rsp[2] = invalid;
            try std.testing.expect(!x86.fredEnabledWith(invalid, valid_emergency, model.fredEntryAddress(), &model));
            cpu.rsp[0] = valid_top;
            cpu.rsp[1] = valid_top;
            cpu.rsp[2] = valid_top;
            cpu.rsp[3] = invalid;
            try std.testing.expect(!x86.fredEnabledWith(valid_top, invalid, model.fredEntryAddress(), &model));
            try std.testing.expectEqual(@as(usize, 0), cpu.fred_reads);
            cpu.rsp[3] = valid_emergency;
        }
    }
}

test "cold BSP identity authentication replaces inherited firmware AUX only after admission" {
    const std = @import("std");
    const previous_index = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_index);
    const Model = struct {
        rdpid: bool = true,
        bsp: bool = true,
        inherited_aux: u32 = 0xFFFF_FFFF,
        reads: usize = 0,
        writes: usize = 0,
        pub fn supportsRdpid(self: *@This()) bool {
            return self.rdpid;
        }
        pub fn readMsr(self: *@This(), msr: u32) u64 {
            std.debug.assert(msr == IA32_APIC_BASE_MSR);
            self.reads += 1;
            return if (self.bsp) APIC_BASE_BSP else 0;
        }
        pub fn initializeLogicalCpu(self: *@This(), index: u8) void {
            std.debug.assert(index == 0 and self.bsp and self.rdpid);
            self.inherited_aux = index;
            self.writes += 1;
            cpu_identity.setIndexForTest(index);
        }
    };
    for ([_]u32{ 0, 1, 15, 16, 0xFFFF_FFFF }) |firmware_aux| {
        for ([_]bool{ false, true }) |rdpid| {
            for ([_]bool{ false, true }) |bsp| {
                cpu_identity.setIndexForTest(15);
                var model = Model{ .rdpid = rdpid, .bsp = bsp, .inherited_aux = firmware_aux };
                try std.testing.expectEqual(rdpid and bsp, bootstrapIdentityWith(&model));
                try std.testing.expectEqual(@as(usize, if (rdpid) 1 else 0), model.reads);
                try std.testing.expectEqual(@as(usize, if (rdpid and bsp) 1 else 0), model.writes);
                try std.testing.expectEqual(if (rdpid and bsp) @as(u32, 0) else firmware_aux, model.inherited_aux);
                try std.testing.expectEqual(@as(u8, if (rdpid and bsp) 0 else 15), cpu_identity.currentIndex());
            }
        }
    }
}
