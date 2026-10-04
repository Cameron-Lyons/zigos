//! Same-CPU, cooperative kernel work. The owner retains this object, its stack
//! and callback state through completion. Yield only at explicit I/O boundaries
//! with no spinlock, interrupt context, userspace mapping, or nonexclusive mutable borrow.
const std = @import("std");
const builtin = @import("builtin");
const freestanding = builtin.os.tag == .freestanding;
const Local = if (freestanding) struct {
    var workers: [@import("../../kernel/smp.zig").MAX_CPUS]?*Worker = @splat(null);
} else struct {
    threadlocal var worker: ?*Worker = null;
};

extern fn zigos_worker_swap(save: *usize, restore: *const usize) callconv(.c) void;
extern fn zigos_worker_bootstrap() callconv(.c) void;

const Frame = extern struct {
    control_word: u16 = 0x037f,
    reserved: u16 = 0,
    mxcsr: u32 = 0x1f80,
    r15: usize = 0,
    r14: usize = 0,
    r13: usize,
    r12: usize,
    rbx: usize = 0,
    rbp: usize = 0,
    entry: usize,
};

fn cpuIndex() u8 {
    return if (freestanding) @import("../../kernel/smp.zig").currentCpuIndex() else 0;
}

fn currentSlot() *?*Worker {
    return if (freestanding) &Local.workers[cpuIndex()] else &Local.worker;
}

pub fn current() ?*Worker {
    return currentSlot().*;
}

fn requireContext() !void {
    if (builtin.cpu.arch != .x86_64) @compileError("native workers require x86-64");
    if (freestanding) {
        const x86 = @import("../../arch/x86.zig");
        if (@import("../../kernel/interrupts/context.zig").active()) return error.InterruptContext;
        if (cpuIndex() != 0) return error.WrongCpu;
        if (!@import("../../kernel/memory/paging64.zig").kernelAddressSpaceActive()) return error.UserAddressSpaceActive;
        if (x86.readCr4() & x86.CR4_CET != 0 and x86.readMsr(x86.IA32_S_CET_MSR) & x86.CET_SH_STK_EN != 0)
            return error.SupervisorShadowStackUnsupported;
    }
}

pub const Worker = struct {
    pub const State = enum { idle, suspended, running, complete };
    stack: []align(16) u8,
    caller_sp: usize = 0,
    worker_sp: usize = 0,
    context: *anyopaque = undefined,
    run_fn: *const fn (*anyopaque) void = undefined,
    state: State = .idle,
    owner_cpu: u8 = 0,
    cancel_requested: bool = false,

    pub fn start(self: *Worker, context: *anyopaque, run_fn: *const fn (*anyopaque) void) !void {
        try requireContext();
        if (self.state == .running or self.state == .suspended) return error.WorkerBusy;
        if (current() != null) return error.NestedWorker;
        if (self.stack.len < 4096 or self.stack.len % 16 != 0) return error.InvalidWorkerStack;
        std.crypto.secureZero(u8, self.stack);
        const frame: *Frame = @ptrCast(@alignCast(self.stack.ptr + self.stack.len - @sizeOf(Frame)));
        frame.* = .{ .r13 = @intFromPtr(&enter), .r12 = @intFromPtr(self), .entry = @intFromPtr(&zigos_worker_bootstrap) };
        self.worker_sp = @intFromPtr(frame);
        self.caller_sp = 0;
        self.context = context;
        self.run_fn = run_fn;
        self.owner_cpu = cpuIndex();
        self.cancel_requested = false;
        self.state = .suspended;
    }

    pub fn step(self: *Worker) !void {
        try requireContext();
        if (self.owner_cpu != cpuIndex()) return error.WrongCpu;
        if (current() != null) return error.NestedWorker;
        if (self.state != .suspended) return error.WorkerNotSuspended;
        self.state = .running;
        currentSlot().* = self;
        zigos_worker_swap(&self.caller_sp, &self.worker_sp);
        std.debug.assert(current() == null and self.state != .running);
        if (self.state == .complete) {
            std.crypto.secureZero(u8, self.stack);
            self.worker_sp = 0;
            self.caller_sp = 0;
        }
    }

    pub fn cancel(self: *Worker) void {
        if (self.state == .suspended or self.state == .running) self.cancel_requested = true;
    }

    pub fn yield(self: *Worker) void {
        requireContext() catch @panic("worker yielded outside its owner context");
        std.debug.assert(current() == self and self.state == .running);
        self.state = .suspended;
        currentSlot().* = null;
        zigos_worker_swap(&self.worker_sp, &self.caller_sp);
        std.debug.assert(current() == self and self.state == .running);
    }

    fn enter(context: *anyopaque) callconv(.c) noreturn {
        const self: *Worker = @ptrCast(@alignCast(context));
        self.run_fn(self.context);
        self.state = .complete;
        currentSlot().* = null;
        zigos_worker_swap(&self.worker_sp, &self.caller_sp);
        unreachable;
    }
};

comptime {
    if (@sizeOf(Frame) != 64 or @offsetOf(Frame, "r12") != 32 or @offsetOf(Frame, "entry") != 56)
        @compileError("worker assembly frame layout changed");
}

test "cooperative worker preserves suspended locals cancellation and stack erasure" {
    const Fixture = struct {
        steps: usize = 0,
        checksum: u64 = 0,
        cancelled: bool = false,
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            var secret: [1024]u8 = @splat(0x9b);
            defer std.crypto.secureZero(u8, &secret);
            for (0..8) |index| {
                self.steps += 1;
                secret[index] ^= @intCast(index);
                current().?.yield();
                std.debug.assert(secret[900] == 0x9b);
                if (current().?.cancel_requested) {
                    self.cancelled = true;
                    return;
                }
                self.checksum += secret[index];
            }
        }
    };
    var stack: [32 * 1024]u8 align(16) = undefined;
    var worker = Worker{ .stack = &stack };
    var fixture = Fixture{};
    try worker.start(&fixture, Fixture.run);
    try worker.step();
    try std.testing.expectEqual(@as(usize, 1), fixture.steps);
    try std.testing.expect(current() == null);
    try std.testing.expectError(error.WorkerBusy, worker.start(&fixture, Fixture.run));
    worker.cancel();
    try worker.step();
    try std.testing.expect(fixture.cancelled and worker.state == .complete);
    try std.testing.expect(std.mem.allEqual(u8, &stack, 0));
    try std.testing.expectError(error.WorkerNotSuspended, worker.step());
    fixture = .{};
    try worker.start(&fixture, Fixture.run);
    for (0..9) |_| try worker.step();
    try std.testing.expectEqual(@as(usize, 8), fixture.steps);
    try std.testing.expectEqual(@as(u64, 1244), fixture.checksum);
    try std.testing.expect(!fixture.cancelled and worker.state == .complete);
    try std.testing.expect(std.mem.allEqual(u8, &stack, 0));
}

test "cooperative worker isolates floating point controls and rejects nested entry" {
    const Controls = struct {
        x87: u16 = 0,
        simd: u32 = 0,
        fn read() @This() {
            var state: @This() = .{};
            asm volatile ("fnstcw (%%rax)"
                :
                : [out] "{rax}" (&state.x87),
                : .{ .memory = true });
            asm volatile ("stmxcsr (%%rax)"
                :
                : [out] "{rax}" (&state.simd),
                : .{ .memory = true });
            return state;
        }
        fn write(self: @This()) void {
            asm volatile ("fldcw (%%rax)"
                :
                : [value] "{rax}" (&self.x87),
                : .{ .memory = true });
            asm volatile ("ldmxcsr (%%rax)"
                :
                : [value] "{rax}" (&self.simd),
                : .{ .memory = true });
        }
    };
    const Fixture = struct {
        nested: Worker = .{ .stack = &.{} },
        nested_rejected: bool = false,
        restored: bool = false,
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.nested.start(self, run) catch |err| {
                self.nested_rejected = err == error.NestedWorker;
            };
            const controls = Controls{ .x87 = 0x0b7f, .simd = 0x5f80 };
            controls.write();
            current().?.yield();
            const restored = Controls.read();
            self.restored = restored.x87 == controls.x87 and restored.simd == controls.simd;
        }
    };
    const original = Controls.read();
    defer original.write();
    const caller = Controls{ .x87 = 0x077f, .simd = 0x3f80 };
    caller.write();
    var stack: [32 * 1024]u8 align(16) = undefined;
    var worker = Worker{ .stack = &stack };
    var fixture = Fixture{};
    try worker.start(&fixture, Fixture.run);
    try worker.step();
    try std.testing.expectEqualDeep(caller, Controls.read());
    try worker.step();
    try std.testing.expectEqualDeep(caller, Controls.read());
    try std.testing.expect(fixture.nested_rejected and fixture.restored);
}
