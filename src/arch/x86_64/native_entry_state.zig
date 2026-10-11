const std = @import("std");
const cpu_identity = @import("../../kernel/cpu_identity.zig");

pub const ENTRY_PKU: u8 = 1;
pub const ENTRY_FRED: u8 = 2;
pub const ENTRY_READY: u8 = 4;

// Preserve the established GS fields and isolate both cache lines of each CPU.
// A continuation belongs to the CPU that entered userspace. Runtime ownership
// admission remains responsible for deciding whether that CPU may dispatch.
pub const State = extern struct {
    kernel_stack_top: usize align(128) = 0,
    user_stack_pointer: usize = 0,
    kernel_port: usize = 0,
    active_task_id: u64 = 0,
    native_entry_modes: u8 = 0,
    _mode_padding: [7]u8 = @splat(0),
    userspace_xstate: usize = 0,
    kernel_xstate: usize = 0,
    resume_rsp: usize = 0,
    resume_rip: usize = 0,
    resume_requested: u32 = 0,
    _reserved: [52]u8 = @splat(0),
};

var states: [cpu_identity.MAX_CPUS]State = @splat(.{});

pub inline fn stateForCpu(index: u8) *volatile State {
    if (index >= cpu_identity.MAX_CPUS) @panic("invalid native entry CPU index");
    return &states[index];
}

pub inline fn current() *volatile State {
    return stateForCpu(cpu_identity.currentIndex());
}

// Hardware GS and CPU identity publication remain the native-entry owner's job.
pub fn initializeCpu(index: u8, stack_top: usize) *volatile State {
    const state = stateForCpu(index);
    state.* = .{ .kernel_stack_top = stack_top };
    return state;
}

pub fn clearContinuation() void {
    const state = current();
    state.userspace_xstate = 0;
    state.kernel_xstate = 0;
    state.resume_rsp = 0;
    state.resume_rip = 0;
    state.resume_requested = 0;
}

comptime {
    if (@sizeOf(usize) != 8 or @sizeOf(State) != 128 or @alignOf(State) != 128 or
        @offsetOf(State, "kernel_stack_top") != 0 or @offsetOf(State, "user_stack_pointer") != 8 or
        @offsetOf(State, "kernel_port") != 16 or @offsetOf(State, "active_task_id") != 24 or
        @offsetOf(State, "native_entry_modes") != 32 or @offsetOf(State, "userspace_xstate") != 40 or
        @offsetOf(State, "kernel_xstate") != 48 or @offsetOf(State, "resume_rsp") != 56 or
        @offsetOf(State, "resume_rip") != 64 or @offsetOf(State, "resume_requested") != 72)
    {
        @compileError("native entry GS state must preserve its x86-64 assembly ABI");
    }
}

fn assemblyConstant(name: []const u8) !usize {
    var lines = std.mem.tokenizeScalar(u8, @embedFile("native_entry_state.inc"), '\n');
    var value: ?usize = null;
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "#define CPU_")) continue;
        var definition = std.mem.tokenizeAny(u8, trimmed[8..], " \t");
        if (!std.mem.eql(u8, definition.next() orelse return error.InvalidAssemblyConstant, name)) continue;
        if (value != null) return error.DuplicateAssemblyConstant;
        value = try std.fmt.parseInt(usize, definition.next() orelse return error.InvalidAssemblyConstant, 0);
        if (definition.next() != null) return error.InvalidAssemblyConstant;
    }
    return value orelse error.MissingAssemblyConstant;
}

test "native entry assembly constants match every GS field and immutable mode bit" {
    inline for (.{
        .{ "CPU_KERNEL_STACK_TOP", @offsetOf(State, "kernel_stack_top") },
        .{ "CPU_USER_STACK_POINTER", @offsetOf(State, "user_stack_pointer") },
        .{ "CPU_KERNEL_PORT", @offsetOf(State, "kernel_port") },
        .{ "CPU_ACTIVE_TASK_ID", @offsetOf(State, "active_task_id") },
        .{ "CPU_NATIVE_ENTRY_MODES", @offsetOf(State, "native_entry_modes") },
        .{ "CPU_USERSPACE_XSTATE", @offsetOf(State, "userspace_xstate") },
        .{ "CPU_KERNEL_XSTATE", @offsetOf(State, "kernel_xstate") },
        .{ "CPU_RESUME_RSP", @offsetOf(State, "resume_rsp") },
        .{ "CPU_RESUME_RIP", @offsetOf(State, "resume_rip") },
        .{ "CPU_RESUME_REQUESTED", @offsetOf(State, "resume_requested") },
        .{ "CPU_STATE_BYTES", @sizeOf(State) },
        .{ "CPU_STATE_ALIGNMENT", @alignOf(State) },
        .{ "CPU_ENTRY_PKU", ENTRY_PKU },
        .{ "CPU_ENTRY_FRED", ENTRY_FRED },
        .{ "CPU_ENTRY_READY", ENTRY_READY },
    }) |item| try std.testing.expectEqual(@as(usize, item[1]), try assemblyConstant(item[0]));
}

test "all native CPU slots select and clear independent continuations in adversarial order" {
    const previous = states;
    const previous_index = cpu_identity.currentIndex();
    defer {
        states = previous;
        cpu_identity.setIndexForTest(previous_index);
    }
    var expected: [cpu_identity.MAX_CPUS]State = undefined;
    for (&expected, 0..) |*state, index| {
        state.* = canaryState(index);
        stateForCpu(@intCast(index)).* = state.*;
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(stateForCpu(@intCast(index))) % 128);
        if (index != 0) try std.testing.expectEqual(@as(usize, 128), @intFromPtr(stateForCpu(@intCast(index))) - @intFromPtr(stateForCpu(@intCast(index - 1))));
    }
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index = adversarialIndex(position);
        cpu_identity.setIndexForTest(index);
        try std.testing.expectEqual(@intFromPtr(stateForCpu(index)), @intFromPtr(current()));
        try std.testing.expectEqualDeep(expected[index], current().*);
        clearContinuation();
        expected[index].userspace_xstate = 0;
        expected[index].kernel_xstate = 0;
        expected[index].resume_rsp = 0;
        expected[index].resume_rip = 0;
        expected[index].resume_requested = 0;
        for (&expected, 0..) |*neighbor, neighbor_index|
            try std.testing.expectEqualDeep(neighbor.*, stateForCpu(@intCast(neighbor_index)).*);
    }
}

test "initializing each native CPU resets exactly its slot without changing logical selection" {
    const previous = states;
    const previous_index = cpu_identity.currentIndex();
    defer {
        states = previous;
        cpu_identity.setIndexForTest(previous_index);
    }
    var expected: [cpu_identity.MAX_CPUS]State = undefined;
    for (&expected, 0..) |*state, index| {
        state.* = canaryState(index);
        stateForCpu(@intCast(index)).* = state.*;
    }
    for (0..cpu_identity.MAX_CPUS) |position| {
        const index = adversarialIndex(position);
        const selected: u8 = @intCast((@as(usize, index) + 1) % cpu_identity.MAX_CPUS);
        cpu_identity.setIndexForTest(selected);
        const stack_top = 0xffff_8000_7000_0000 + @as(usize, index) * 4096;
        try std.testing.expectEqual(@intFromPtr(stateForCpu(index)), @intFromPtr(initializeCpu(index, stack_top)));
        try std.testing.expectEqual(selected, cpu_identity.currentIndex());
        expected[index] = .{ .kernel_stack_top = stack_top };
        for (&expected, 0..) |*neighbor, neighbor_index|
            try std.testing.expectEqualDeep(neighbor.*, stateForCpu(@intCast(neighbor_index)).*);
    }
}

fn adversarialIndex(position: usize) u8 {
    return @intCast(if (position % 2 == 0) cpu_identity.MAX_CPUS - 1 - position / 2 else position / 2);
}

fn canaryState(index: usize) State {
    return .{
        .kernel_stack_top = 0xffff_8000_1000_0000 + index * 4096,
        .user_stack_pointer = 0x7000_0000 + index * 4096,
        .kernel_port = 0xffff_8000_2000_0000 + index * 128,
        .active_task_id = 100 + index,
        .native_entry_modes = ENTRY_READY | @as(u8, @intCast(index & 3)),
        ._mode_padding = @splat(@intCast(index + 1)),
        .userspace_xstate = 0xffff_8000_3000_0000 + index * 4096,
        .kernel_xstate = 0xffff_8000_4000_0000 + index * 4096,
        .resume_rsp = 0xffff_8000_5000_0000 + index * 4096,
        .resume_rip = 0xffff_ffff_8000_0000 + index * 64,
        .resume_requested = @intCast(1000 + index),
        ._reserved = @splat(@intCast(index + 17)),
    };
}
