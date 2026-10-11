const std = @import("std");
const cpu_identity = @import("../cpu_identity.zig");

pub const GdtPtr = extern struct {
    limit: u16,
    base: usize align(1),
};

pub const Tss = extern struct {
    reserved0: u32 = 0,
    rsp0: u64 align(1) = 0,
    rsp1: u64 align(1) = 0,
    rsp2: u64 align(1) = 0,
    reserved1: u64 align(1) = 0,
    ist1: u64 align(1) = 0,
    ist2: u64 align(1) = 0,
    ist3: u64 align(1) = 0,
    ist4: u64 align(1) = 0,
    ist5: u64 align(1) = 0,
    ist6: u64 align(1) = 0,
    ist7: u64 align(1) = 0,
    reserved2: u64 align(1) = 0,
    reserved3: u16 = 0,
    iomap_base: u16 = @sizeOf(Tss),
};

pub const KERNEL_CODE_SEG: u16 = 0x08;
pub const KERNEL_DATA_SEG: u16 = 0x10;
pub const USER_DATA_SEG: u16 = 0x18;
pub const USER_CODE_SEG: u16 = 0x20;
pub const TSS_SEG: u16 = 0x28;
pub const DOUBLE_FAULT_IST_INDEX: u3 = 1;

const NULL_DESCRIPTOR_INDEX = 0;
const KERNEL_CODE_DESCRIPTOR_INDEX = 1;
const KERNEL_DATA_DESCRIPTOR_INDEX = 2;
const USER_DATA_DESCRIPTOR_INDEX = 3;
const USER_CODE_DESCRIPTOR_INDEX = 4;
const TSS_DESCRIPTOR_LOW_INDEX = 5;
const TSS_DESCRIPTOR_HIGH_INDEX = 6;

const PRESENT: u8 = 0x80;
const DPL_USER: u8 = 0x60;
const SEGMENT: u8 = 0x10;
const EXECUTABLE: u8 = 0x08;
const RW: u8 = 0x02;
const ACCESSED: u8 = 0x01;
const AVAILABLE_TSS: u8 = 0x09;
const GRANULARITY: u4 = 0x8;
const LONG_MODE: u4 = 0x2;
const SIZE_32: u4 = 0x4;
const FLAT_SEGMENT_LIMIT: u20 = 0xFFFFF;
pub const DOUBLE_FAULT_STACK_GUARD_BYTES: usize = 4096;
pub const DOUBLE_FAULT_STACK_USABLE_BYTES: usize = 16 * 1024;
pub const DOUBLE_FAULT_STACK_TOTAL_BYTES: usize = DOUBLE_FAULT_STACK_GUARD_BYTES + DOUBLE_FAULT_STACK_USABLE_BYTES;
pub const DOUBLE_FAULT_STACK_ALIGNMENT: usize = DOUBLE_FAULT_STACK_GUARD_BYTES;
pub const DoubleFaultStackStorage = [DOUBLE_FAULT_STACK_TOTAL_BYTES]u8;
pub const DOUBLE_FAULT_STACK_STORAGE_BYTES: usize = cpu_identity.MAX_CPUS * DOUBLE_FAULT_STACK_TOTAL_BYTES;
const DoubleFaultStacks = [cpu_identity.MAX_CPUS]DoubleFaultStackStorage;

const CpuTables = struct {
    gdt: [7]u64 align(8) = @splat(0),
    gdt_ptr: GdtPtr = undefined,
    tss: Tss align(16) = .{},
    initialized: bool = false,
};

var cpu_tables: [cpu_identity.MAX_CPUS]CpuTables = @splat(.{});
var double_fault_stacks: ?*align(DOUBLE_FAULT_STACK_ALIGNMENT) DoubleFaultStacks = null;

const KERNEL_CODE_DESCRIPTOR = segmentDescriptor(
    0,
    FLAT_SEGMENT_LIMIT,
    PRESENT | SEGMENT | EXECUTABLE | RW | ACCESSED,
    GRANULARITY | LONG_MODE,
);
const KERNEL_DATA_DESCRIPTOR = segmentDescriptor(
    0,
    FLAT_SEGMENT_LIMIT,
    PRESENT | SEGMENT | RW | ACCESSED,
    GRANULARITY | SIZE_32,
);
const USER_CODE_DESCRIPTOR = segmentDescriptor(
    0,
    FLAT_SEGMENT_LIMIT,
    PRESENT | DPL_USER | SEGMENT | EXECUTABLE | RW | ACCESSED,
    GRANULARITY | LONG_MODE,
);
const USER_DATA_DESCRIPTOR = segmentDescriptor(
    0,
    FLAT_SEGMENT_LIMIT,
    PRESENT | DPL_USER | SEGMENT | RW | ACCESSED,
    GRANULARITY | SIZE_32,
);

extern fn gdt_flush(gdt_ptr: *const GdtPtr) void;
extern fn tss_flush() void;

pub fn bindDoubleFaultStacks(storage: *anyopaque) bool {
    if (double_fault_stacks != null) return false;
    double_fault_stacks = @ptrCast(@alignCast(storage));
    return true;
}

pub fn doubleFaultStackGuardAddress() usize {
    return doubleFaultStackGuardAddressForCpu(cpu_identity.currentIndex());
}

pub fn doubleFaultStackGuardAddressForCpu(index: u8) usize {
    const storage = double_fault_stacks orelse @panic("double-fault stack storage is not bound");
    if (index >= cpu_identity.MAX_CPUS) @panic("invalid double-fault stack CPU");
    return @intFromPtr(&storage[index]);
}

pub fn doubleFaultStackTop() usize {
    return doubleFaultStackGuardAddress() + DOUBLE_FAULT_STACK_TOTAL_BYTES;
}

pub fn init() void {
    initCpu(0);
}

pub fn initCpu(index: u8) void {
    if (index >= cpu_identity.MAX_CPUS) @panic("invalid GDT CPU");
    initializeCpuTables(
        &cpu_tables[index],
        doubleFaultStackGuardAddressForCpu(index) + DOUBLE_FAULT_STACK_TOTAL_BYTES,
        HardwareLoad{},
    );
}

const HardwareLoad = struct {
    fn load(_: @This(), pointer: *const GdtPtr) void {
        gdt_flush(pointer);
        tss_flush();
    }
};

fn initializeCpuTables(state: *CpuTables, emergency_stack_top: usize, loader: anytype) void {
    // LTR makes this CPU's descriptor busy. Never reload it or rewrite the
    // descriptor while another CPU still uses its own independent table.
    if (state.initialized) return;
    state.gdt[NULL_DESCRIPTOR_INDEX] = 0;
    state.gdt[KERNEL_CODE_DESCRIPTOR_INDEX] = KERNEL_CODE_DESCRIPTOR;
    state.gdt[KERNEL_DATA_DESCRIPTOR_INDEX] = KERNEL_DATA_DESCRIPTOR;
    state.gdt[USER_CODE_DESCRIPTOR_INDEX] = USER_CODE_DESCRIPTOR;
    state.gdt[USER_DATA_DESCRIPTOR_INDEX] = USER_DATA_DESCRIPTOR;
    state.tss = .{ .ist1 = emergency_stack_top };
    writeTssDescriptor(state);
    state.gdt_ptr = .{
        .limit = @sizeOf(@TypeOf(state.gdt)) - 1,
        .base = @intFromPtr(&state.gdt),
    };
    loader.load(&state.gdt_ptr);
    state.initialized = true;
}

fn currentTables() *CpuTables {
    return &cpu_tables[cpu_identity.currentIndex()];
}

pub fn setKernelStack(stack: usize) void {
    const rsp0: *align(1) volatile u64 = &currentTables().tss.rsp0;
    rsp0.* = stack;
}

// A software TSS pointer is insufficient: the currently loaded GDTR and TR
// must select this CPU's initialized busy descriptor before stack mutation.
pub inline fn kernelStackOwnerIsLoaded(gdtr: GdtPtr, task_register: u16) bool {
    const state = currentTables();
    const storage = double_fault_stacks orelse return false;
    const emergency_top = @intFromPtr(&storage[cpu_identity.currentIndex()]) + DOUBLE_FAULT_STACK_TOTAL_BYTES;
    const low: *volatile u64 = &state.gdt[TSS_DESCRIPTOR_LOW_INDEX];
    const high: *volatile u64 = &state.gdt[TSS_DESCRIPTOR_HIGH_INDEX];
    const descriptor = low.*;
    const base = ((descriptor >> 16) & 0xFF_FFFF) |
        ((descriptor >> 32) & 0xFF00_0000) | (high.* << 32);
    const limit = (descriptor & 0xFFFF) | ((descriptor >> 32) & 0xF0000);
    const ist1: *align(1) volatile u64 = &state.tss.ist1;
    return state.initialized and task_register == TSS_SEG and
        gdtr.base == @intFromPtr(&state.gdt) and gdtr.limit == @sizeOf(@TypeOf(state.gdt)) - 1 and
        state.gdt_ptr.base == gdtr.base and state.gdt_ptr.limit == gdtr.limit and
        base == @intFromPtr(&state.tss) and limit == @sizeOf(Tss) - 1 and
        ((descriptor >> 40) & 0xFF) == PRESENT | AVAILABLE_TSS | 2 and
        ((descriptor >> 52) & 0xF) == 0 and high.* >> 32 == 0 and
        ist1.* == emergency_top and state.tss.iomap_base == @sizeOf(Tss);
}

pub inline fn kernelStackMatches(stack: usize) bool {
    const state = currentTables();
    const rsp0: *align(1) volatile u64 = &state.tss.rsp0;
    const ist1: *align(1) volatile u64 = &state.tss.ist1;
    return rsp0.* == stack and ist1.* == doubleFaultStackTop();
}

pub const Testing = if (@import("builtin").is_test) struct {
    pub const Snapshot = struct {
        tables: [cpu_identity.MAX_CPUS]CpuTables,
        stacks: ?*align(DOUBLE_FAULT_STACK_ALIGNMENT) DoubleFaultStacks,

        pub fn restore(self: *const @This()) void {
            cpu_tables = self.tables;
            double_fault_stacks = self.stacks;
        }
    };

    pub fn install() Snapshot {
        const previous = Snapshot{ .tables = cpu_tables, .stacks = double_fault_stacks };
        cpu_tables = @splat(.{});
        // Only the addresses are used; no test dereferences this stack storage.
        double_fault_stacks = @ptrFromInt(0xFFFF_8000_0200_0000);
        var loads: usize = 0;
        for (&cpu_tables, 0..) |*state, index| initializeCpuTables(state, @intFromPtr(double_fault_stacks.?) + (index + 1) * DOUBLE_FAULT_STACK_TOTAL_BYTES, ModelLoad{ .count = &loads });
        return previous;
    }

    pub fn gdtr(index: u8) GdtPtr {
        return cpu_tables[index].gdt_ptr;
    }

    pub fn tss(index: u8) *Tss {
        return &cpu_tables[index].tss;
    }

    pub fn initialized(index: u8, value: bool) void {
        cpu_tables[index].initialized = value;
    }
} else struct {};

pub fn configureDoubleFaultIst() void {
    currentTables().tss.ist1 = doubleFaultStackTop();
}

pub fn userDataDescriptor() u64 {
    return currentTables().gdt[USER_DATA_DESCRIPTOR_INDEX];
}

pub fn userCodeDescriptor() u64 {
    return currentTables().gdt[USER_CODE_DESCRIPTOR_INDEX];
}

fn segmentDescriptor(base: u32, limit: u20, access: u8, flags: u4) u64 {
    return @as(u64, limit & 0xFFFF) |
        (@as(u64, base & 0xFF_FFFF) << 16) |
        (@as(u64, access) << 40) |
        (@as(u64, (limit >> 16) & 0xF) << 48) |
        (@as(u64, flags) << 52) |
        (@as(u64, (base >> 24) & 0xFF) << 56);
}

fn writeTssDescriptor(state: *CpuTables) void {
    const base: u64 = @intFromPtr(&state.tss);
    const limit: u20 = @sizeOf(Tss) - 1;
    state.gdt[TSS_DESCRIPTOR_LOW_INDEX] = segmentDescriptor(
        @truncate(base),
        limit,
        PRESENT | AVAILABLE_TSS,
        0,
    );
    state.gdt[TSS_DESCRIPTOR_HIGH_INDEX] = base >> 32;
}

comptime {
    if (@sizeOf(Tss) != 104) @compileError("x86-64 TSS must be 104 bytes");
    if (@sizeOf(GdtPtr) != 10) @compileError("x86-64 GDTR operand must be 10 bytes");
    if (@sizeOf(DoubleFaultStackStorage) != 20 * 1024 or
        DOUBLE_FAULT_STACK_USABLE_BYTES != 16 * 1024)
    {
        @compileError("double-fault stack must retain a guarded 16 KiB emergency capacity");
    }
    if (KERNEL_CODE_DESCRIPTOR != 0x00AF_9B00_0000_FFFF or
        KERNEL_DATA_DESCRIPTOR != 0x00CF_9300_0000_FFFF or
        USER_CODE_DESCRIPTOR != 0x00AF_FB00_0000_FFFF or
        USER_DATA_DESCRIPTOR != 0x00CF_F300_0000_FFFF)
    {
        @compileError("x86-64 flat descriptors must be valid without processor mutation");
    }
    if (segmentDescriptor(0, FLAT_SEGMENT_LIMIT, 0x9A, 0xA) != 0x00AF_9A00_0000_FFFF) {
        @compileError("x86-64 code descriptor encoding diverged from the hardware ABI");
    }
    if (segmentDescriptor(0x1234_5678, 103, 0x89, 0) != 0x1200_8934_5678_0067) {
        @compileError("x86-64 TSS descriptor encoding diverged from the hardware ABI");
    }
}

const ModelLoad = struct {
    count: *usize,

    fn load(self: @This(), pointer: *const GdtPtr) void {
        const descriptors: *[7]u64 = @ptrFromInt(pointer.base);
        // Model LTR's available-to-busy transition on this descriptor alone.
        std.debug.assert((descriptors[TSS_DESCRIPTOR_LOW_INDEX] >> 40) & 0xF == AVAILABLE_TSS);
        descriptors[TSS_DESCRIPTOR_LOW_INDEX] |= @as(u64, 2) << 40;
        self.count.* += 1;
    }
};

test "each CPU loads an independent available TSS once and retains its busy descriptor" {
    var tables: [cpu_identity.MAX_CPUS]CpuTables = @splat(.{});
    var loads: [cpu_identity.MAX_CPUS]usize = @splat(0);
    // Alternate the highest and lowest remaining slots so AP admission never
    // relies on earlier logical CPUs having initialized their descriptors.
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index = if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2;
        const state = &tables[index];
        const stack_top = 0xFFFF_8000_0200_0000 + (index + 1) * DOUBLE_FAULT_STACK_TOTAL_BYTES;
        initializeCpuTables(state, stack_top, ModelLoad{ .count = &loads[index] });
        const tss_base = ((state.gdt[TSS_DESCRIPTOR_LOW_INDEX] >> 16) & 0xFF_FFFF) |
            ((state.gdt[TSS_DESCRIPTOR_LOW_INDEX] >> 32) & 0xFF00_0000) |
            (state.gdt[TSS_DESCRIPTOR_HIGH_INDEX] << 32);
        try std.testing.expectEqual(@intFromPtr(&state.tss), tss_base);
        try std.testing.expectEqual(@intFromPtr(&state.gdt), state.gdt_ptr.base);
        try std.testing.expectEqual(@as(u16, 55), state.gdt_ptr.limit);
        try std.testing.expectEqual(@as(u64, 0xB), (state.gdt[TSS_DESCRIPTOR_LOW_INDEX] >> 40) & 0xF);
        try std.testing.expectEqual(@as(u64, stack_top), state.tss.ist1);
        try std.testing.expectEqual(@as(u16, @sizeOf(Tss)), state.tss.iomap_base);
        // A repeated setup must not reset the busy flag, RSP0 or IST state.
        state.tss.rsp0 = 0xFFFF_8000_1000_0000 + index * 4096;
        initializeCpuTables(state, 0, ModelLoad{ .count = &loads[index] });
        try std.testing.expectEqual(@as(usize, 1), loads[index]);
        try std.testing.expectEqual(@as(u64, stack_top), state.tss.ist1);
        try std.testing.expectEqual(@as(u64, 0xFFFF_8000_1000_0000 + index * 4096), state.tss.rsp0);
        for (tables, 0..) |earlier, earlier_index| {
            if (earlier_index == index or !earlier.initialized) continue;
            try std.testing.expect(earlier.gdt_ptr.base != state.gdt_ptr.base);
            try std.testing.expect(earlier.tss.ist1 != state.tss.ist1);
            try std.testing.expectEqual(@as(u64, 0xB), (earlier.gdt[TSS_DESCRIPTOR_LOW_INDEX] >> 40) & 0xF);
        }
    }
    // Revisit every CPU after all other LTR transitions. None may reset a busy
    // descriptor or adopt another CPU's emergency or ring-transition stack.
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index = cpu_identity.MAX_CPUS - 1 - position;
        initializeCpuTables(&tables[index], 0, ModelLoad{ .count = &loads[index] });
        try std.testing.expectEqual(@as(usize, 1), loads[index]);
        try std.testing.expectEqual(@as(u64, 0xB), (tables[index].gdt[TSS_DESCRIPTOR_LOW_INDEX] >> 40) & 0xF);
        try std.testing.expectEqual(@as(u64, 0xFFFF_8000_0200_0000 + (index + 1) * DOUBLE_FAULT_STACK_TOTAL_BYTES), tables[index].tss.ist1);
        try std.testing.expectEqual(@as(u64, 0xFFFF_8000_1000_0000 + index * 4096), tables[index].tss.rsp0);
    }
}

test "CPU selection isolates RSP0 and guarded emergency stacks" {
    var stacks: DoubleFaultStacks align(DOUBLE_FAULT_STACK_ALIGNMENT) = undefined;
    const previous_tables = cpu_tables;
    const previous_stacks = double_fault_stacks;
    const previous_index = cpu_identity.currentIndex();
    defer {
        cpu_tables = previous_tables;
        double_fault_stacks = previous_stacks;
        cpu_identity.setIndexForTest(previous_index);
    }
    cpu_tables = @splat(.{});
    double_fault_stacks = null;
    try std.testing.expect(bindDoubleFaultStacks(&stacks));
    try std.testing.expect(!bindDoubleFaultStacks(&stacks));
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        setKernelStack(0xFFFF_8000_1000_0000 + index * 4096);
        configureDoubleFaultIst();
    }
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2);
        cpu_identity.setIndexForTest(index);
        const guard = doubleFaultStackGuardAddressForCpu(index);
        try std.testing.expectEqual(@intFromPtr(&stacks) + @as(usize, index) * DOUBLE_FAULT_STACK_TOTAL_BYTES, guard);
        try std.testing.expectEqual(@as(usize, 0), guard % DOUBLE_FAULT_STACK_ALIGNMENT);
        try std.testing.expectEqual(guard, doubleFaultStackGuardAddress());
        try std.testing.expectEqual(guard + DOUBLE_FAULT_STACK_TOTAL_BYTES, doubleFaultStackTop());
        try std.testing.expectEqual(@as(u64, doubleFaultStackTop()), currentTables().tss.ist1);
        try std.testing.expectEqual(@as(u64, 0xFFFF_8000_1000_0000 + @as(usize, index) * 4096), currentTables().tss.rsp0);
        if (index > 0) {
            const previous_guard = doubleFaultStackGuardAddressForCpu(index - 1);
            try std.testing.expect(previous_guard + DOUBLE_FAULT_STACK_TOTAL_BYTES <= guard);
        }
    }
}

test "cold loaded TSS ownership rejects foreign descriptors and malformed emergency metadata" {
    const previous = Testing.install();
    const previous_index = cpu_identity.currentIndex();
    defer {
        previous.restore();
        cpu_identity.setIndexForTest(previous_index);
    }
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        const state = &cpu_tables[index];
        const expected = state.*;
        try std.testing.expect(kernelStackOwnerIsLoaded(state.gdt_ptr, TSS_SEG));
        for ([_]u64{ @as(u64, 2) << 40, @as(u64, 1) << 16, 1, @as(u64, 1) << 52 }) |bit| {
            state.gdt[TSS_DESCRIPTOR_LOW_INDEX] ^= bit;
            try std.testing.expect(!kernelStackOwnerIsLoaded(state.gdt_ptr, TSS_SEG));
            state.* = expected;
        }
        state.gdt[TSS_DESCRIPTOR_HIGH_INDEX] |= @as(u64, 1) << 32;
        try std.testing.expect(!kernelStackOwnerIsLoaded(state.gdt_ptr, TSS_SEG));
        state.* = expected;
        state.tss.iomap_base -= 1;
        try std.testing.expect(!kernelStackOwnerIsLoaded(state.gdt_ptr, TSS_SEG));
        state.* = expected;
        state.tss.ist1 ^= 64;
        try std.testing.expect(!kernelStackOwnerIsLoaded(state.gdt_ptr, TSS_SEG));
        state.* = expected;
        state.gdt_ptr.base ^= 8;
        try std.testing.expect(!kernelStackOwnerIsLoaded(state.gdt_ptr, TSS_SEG));
        state.* = expected;
        try std.testing.expect(!kernelStackOwnerIsLoaded(cpu_tables[(index + 1) % cpu_identity.MAX_CPUS].gdt_ptr, TSS_SEG));
        try std.testing.expect(!kernelStackOwnerIsLoaded(state.gdt_ptr, TSS_SEG | 3));
    }
}
