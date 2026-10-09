const std = @import("std");
const interrupt_context = @import("context.zig");
const gdt = @import("gdt64.zig");
const idt = @import("idt64.zig");
const io = @import("../utils/io.zig");
const console = @import("../utils/console.zig");
const numfmt = @import("../utils/numfmt.zig");
const timer = @import("../timer/timer.zig");
const intel_i225_hw = @import("../drivers/intel_i225_hw.zig");
const nvme_hw = @import("../drivers/nvme_hw.zig");
const xhci_hw = @import("../drivers/xhci_hw.zig");
const smp = @import("../smp.zig");
const event_wake = @import("../event_wake.zig");
const cpu_identity = @import("../cpu_identity.zig");
const x2apic = @import("x2apic.zig");
const dispatch_transport = @import("../../native/task/dispatch_transport.zig");

const GateHandler = *const fn () callconv(.c) void;

const IDT_INTERRUPT_GATE: u8 = 0x8E;
const EXCEPTION_VECTOR_COUNT: u32 = 32;
const DOUBLE_FAULT_VECTOR: u8 = 8;
const PAGE_FAULT_VECTOR: u32 = 14;
const USERSPACE_YIELD_VECTOR: u8 = 129;
const REQUESTED_PRIVILEGE_LEVEL_MASK: usize = 0x3;
const USER_PRIVILEGE_LEVEL: usize = 0x3;

const PIC_MASTER_DATA_PORT: u16 = 0x21;
const PIC_SLAVE_DATA_PORT: u16 = 0xA1;
const PIC_MASK_ALL: u8 = 0xFF;

extern fn isr0() void;
extern fn isr1() void;
extern fn isr2() void;
extern fn isr3() void;
extern fn isr4() void;
extern fn isr5() void;
extern fn isr6() void;
extern fn isr7() void;
extern fn isr8() void;
extern fn isr9() void;
extern fn isr10() void;
extern fn isr11() void;
extern fn isr12() void;
extern fn isr13() void;
extern fn isr14() void;
extern fn isr15() void;
extern fn isr16() void;
extern fn isr17() void;
extern fn isr18() void;
extern fn isr19() void;
extern fn isr20() void;
extern fn isr21() void;
extern fn isr22() void;
extern fn isr23() void;
extern fn isr24() void;
extern fn isr25() void;
extern fn isr26() void;
extern fn isr27() void;
extern fn isr28() void;
extern fn isr29() void;
extern fn isr30() void;
extern fn isr31() void;
extern fn isr64() void;
extern fn isr65() void;
extern fn isr66() void;
extern fn isr67() void;
extern fn isr112() void;
extern fn isr113() void;
extern fn isr114() void;
extern fn isr115() void;
extern fn isr116() void;
extern fn isr255() void;

const exception_stubs = [_]GateHandler{
    &isr0,
    &isr1,
    &isr2,
    &isr3,
    &isr4,
    &isr5,
    &isr6,
    &isr7,
    &isr8,
    &isr9,
    &isr10,
    &isr11,
    &isr12,
    &isr13,
    &isr14,
    &isr15,
    &isr16,
    &isr17,
    &isr18,
    &isr19,
    &isr20,
    &isr21,
    &isr22,
    &isr23,
    &isr24,
    &isr25,
    &isr26,
    &isr27,
    &isr28,
    &isr29,
    &isr30,
    &isr31,
};

pub const Registers = extern struct {
    ds: usize,
    r15: usize,
    r14: usize,
    r13: usize,
    r12: usize,
    r11: usize,
    r10: usize,
    r9: usize,
    r8: usize,
    edi: usize,
    esi: usize,
    ebp: usize,
    esp: usize,
    ebx: usize,
    edx: usize,
    ecx: usize,
    eax: usize,
    int_no: usize,
    err_code: usize,
    eip: usize,
    cs: usize,
    eflags: usize,
    useresp: usize,
    ss: usize,
};

const exception_messages = [_][]const u8{
    "Division By Zero",
    "Debug",
    "Non Maskable Interrupt",
    "Breakpoint",
    "Into Detected Overflow",
    "Out of Bounds",
    "Invalid Opcode",
    "No Coprocessor",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Bad TSS",
    "Segment Not Present",
    "Stack Fault",
    "General Protection Fault",
    "Page Fault",
    "Unknown Interrupt",
    "Coprocessor Fault",
    "Alignment Check",
    "Machine Check",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
};

pub export fn isrHandler(regs: *Registers) void {
    interrupt_context.enter();
    defer interrupt_context.leave();
    const vector = interruptVector(regs);
    // Owned xstate never lazily arms TS. Unexpected #NM follows the registered
    // user containment handler or the ordinary fatal kernel exception path.
    if (handlerForVector(vector)) |handler| {
        const frame: *InterruptFrame = @ptrCast(regs);
        handler(frame);
        // Device handlers only latch/acknowledge work. Return an interrupted
        // user to the runtime owner so that deferred service can make receivers
        // runnable before the next scheduler tick. Never interrupt kernel work.
        if (frameOriginatesFromUserspace(frame.cs) and
            (vector == timer.INTERRUPT_VECTOR or vector == smp.EXECUTION_STOP_IPI_VECTOR or
                (vector == smp.SYSCALL_REQUEST_IPI_VECTOR and smp.isRuntimeOwner()) or deviceWorkPending(vector)))
        {
            if (@atomicLoad(?InterruptHandler, &runtime_preemption, .acquire)) |hook| hook(frame);
        }
        return;
    }

    if (vector == PAGE_FAULT_VECTOR) {
        const paging = @import("../memory/paging64.zig");
        paging.page_fault_handler(regs);
        return;
    }

    if (vector < EXCEPTION_VECTOR_COUNT) {
        haltUnhandledException(regs);
    }
}
pub const InterruptFrame = Registers;
pub const InterruptHandler = *const fn (regs: *InterruptFrame) void;

// Executor release-publishes a context-free function whose lifetime exceeds
// every CPU registration. Reinitialization may republish the same hook; AP
// acquire readers never inspect the separately mutable BSP policy callback.
var runtime_preemption: ?InterruptHandler = null;

pub fn setRuntimePreemption(handler: InterruptHandler) void {
    @atomicStore(?InterruptHandler, &runtime_preemption, handler, .release);
}

fn deviceWorkPending(vector: usize) bool {
    return switch (vector) {
        intel_i225_hw.INTERRUPT_VECTOR => event_wake.peek().network,
        // NVMe also raises a deferred-work latch. Preserve the same owner
        // boundary without processing completions in this interrupt hook.
        nvme_hw.INTERRUPT_VECTOR => event_wake.peek().nvme,
        xhci_hw.INTERRUPT_VECTOR => event_wake.peek().xhci,
        else => false,
    };
}

// Hosted integration fixtures use the real ISR dispatcher with registered
// latch-only handlers; preserve its shared tables without fake device MMIO.
pub fn withTestHandlers(context: anytype, callback: anytype) !void {
    if (!@import("builtin").is_test) @compileError("ISR fixture state is test-only");
    const saved_exceptions = exception_handlers;
    const saved_external = external_handlers;
    const saved_preemption = @atomicLoad(?InterruptHandler, &runtime_preemption, .acquire);
    defer {
        exception_handlers = saved_exceptions;
        external_handlers = saved_external;
        @atomicStore(?InterruptHandler, &runtime_preemption, saved_preemption, .release);
    }
    try callback(context);
}

const external_handler_vectors = [_]u8{
    timer.INTERRUPT_VECTOR,
    intel_i225_hw.INTERRUPT_VECTOR,
    nvme_hw.INTERRUPT_VECTOR,
    xhci_hw.INTERRUPT_VECTOR,
    smp.TLB_IPI_VECTOR,
    USERSPACE_YIELD_VECTOR,
    timer.SPURIOUS_VECTOR,
};
const HANDLER_STORAGE_SIZE_CEILING_BYTES: usize = 320;

var exception_handlers: [EXCEPTION_VECTOR_COUNT]?InterruptHandler = @as([EXCEPTION_VECTOR_COUNT]?InterruptHandler, @splat(null));
var external_handlers: [external_handler_vectors.len]?InterruptHandler = @as([external_handler_vectors.len]?InterruptHandler, @splat(null));

fn externalHandlerIndex(vector: usize) ?usize {
    inline for (external_handler_vectors, 0..) |registered_vector, index| {
        if (vector == registered_vector) return index;
    }
    return null;
}

fn handlerForVector(vector: usize) ?InterruptHandler {
    // A stop IPI has one immutable handler, rather than another mutable shared
    // registration slot. Delayed IPIs still receive exactly one EOI.
    if (vector == smp.EXECUTION_STOP_IPI_VECTOR) return executionStopInterrupt;
    if (vector == smp.SYSCALL_REQUEST_IPI_VECTOR) return syscallRequestInterrupt;
    if (vector == smp.SYSCALL_COMPLETION_IPI_VECTOR) return syscallCompletionInterrupt;
    if (vector == smp.PREPARED_EXECUTION_IPI_VECTOR) return preparedExecutionInterrupt;
    if (vector < exception_handlers.len) return exception_handlers[vector];
    const index = externalHandlerIndex(vector) orelse return null;
    return external_handlers[index];
}

pub fn registerHandler(vector: u8, handler: InterruptHandler) void {
    if (vector < exception_handlers.len) {
        exception_handlers[vector] = handler;
        return;
    }
    const index = externalHandlerIndex(vector) orelse @panic("unsupported interrupt handler vector");
    external_handlers[index] = handler;
}

pub fn init() void {
    for (exception_stubs, 0..) |stub, vector| {
        setKernelGate(@as(u8, @intCast(vector)), stub);
    }

    gdt.configureDoubleFaultIst();
    idt.setIstGate(
        DOUBLE_FAULT_VECTOR,
        &isr8,
        gdt.KERNEL_CODE_SEG,
        IDT_INTERRUPT_GATE,
        gdt.DOUBLE_FAULT_IST_INDEX,
    );
    registerHandler(DOUBLE_FAULT_VECTOR, doubleFaultInterrupt);

    disableLegacyPic();
    setKernelGate(timer.INTERRUPT_VECTOR, &isr64);
    registerHandler(timer.INTERRUPT_VECTOR, timerInterrupt);
    setKernelGate(intel_i225_hw.INTERRUPT_VECTOR, &isr65);
    registerHandler(intel_i225_hw.INTERRUPT_VECTOR, i225Interrupt);
    setKernelGate(nvme_hw.INTERRUPT_VECTOR, &isr66);
    registerHandler(nvme_hw.INTERRUPT_VECTOR, nvmeInterrupt);
    setKernelGate(xhci_hw.INTERRUPT_VECTOR, &isr67);
    registerHandler(xhci_hw.INTERRUPT_VECTOR, xhciInterrupt);
    setKernelGate(smp.TLB_IPI_VECTOR, &isr112);
    registerHandler(smp.TLB_IPI_VECTOR, tlbIpiInterrupt);
    setKernelGate(smp.EXECUTION_STOP_IPI_VECTOR, &isr113);
    setKernelGate(smp.SYSCALL_REQUEST_IPI_VECTOR, &isr114);
    setKernelGate(smp.SYSCALL_COMPLETION_IPI_VECTOR, &isr115);
    setKernelGate(smp.PREPARED_EXECUTION_IPI_VECTOR, &isr116);
    setKernelGate(timer.SPURIOUS_VECTOR, &isr255);
    registerHandler(timer.SPURIOUS_VECTOR, spuriousInterrupt);

    idt.init();
}

fn doubleFaultInterrupt(frame: *InterruptFrame) void {
    const panic_utils = @import("../utils/panic.zig");
    panic_utils.panic(
        "DOUBLE FAULT: instruction=0x{x} stack=0x{x} frame=0x{x}",
        .{ frame.eip, frame.useresp, frame.ebp },
    );
}

fn timerInterrupt(_: *InterruptFrame) void {
    timer.handleInterrupt();
    // Each processor services its local timer. The BSP alone owns the runtime
    // event loop; an AP tick must not wake or advance that loop.
    if (cpu_identity.currentIndex() == 0) {
        event_wake.raise(.timer);
        event_wake.raise(.scheduler);
    }
}

fn i225Interrupt(_: *InterruptFrame) void {
    const virtio_net_hw = @import("../drivers/virtio_net_hw.zig");
    if (virtio_net_hw.isolationDomain() != null) {
        virtio_net_hw.handleInterrupt();
    } else {
        intel_i225_hw.handleInterrupt();
    }
    event_wake.raise(.network);
}

fn nvmeInterrupt(_: *InterruptFrame) void {
    nvme_hw.handleInterrupt();
    event_wake.raise(.nvme);
}

fn xhciInterrupt(_: *InterruptFrame) void {
    xhci_hw.handleInterrupt();
    event_wake.raise(.xhci);
}

fn tlbIpiInterrupt(_: *InterruptFrame) void {
    smp.handleTlbIpi();
}

fn executionStopInterrupt(_: *InterruptFrame) void {
    // EOI acknowledges only this interrupt. Execution remains leased until its
    // owner completes the ordinary checked return and publishes a separate ACK.
    acknowledgeExecutionStopInterrupt();
}

fn preparedExecutionInterrupt(_: *InterruptFrame) void {
    acknowledgePreparedExecutionInterrupt();
}

// The prompt is durable image-owned state, independent of any command or
// issuer. A late or duplicate vector must never claim/run an execution lease.
pub inline fn acknowledgePreparedExecutionInterrupt() void {
    x2apic.acknowledge();
    dispatch_transport.global.notePrompt() catch return;
}

pub inline fn acknowledgeExecutionStopInterrupt() void {
    x2apic.acknowledge();
}

fn syscallRequestInterrupt(_: *InterruptFrame) void {
    acknowledgeSyscallRequestInterrupt();
}

pub inline fn acknowledgeSyscallRequestInterrupt() void {
    x2apic.acknowledge();
    if (smp.isRuntimeOwner()) event_wake.raise(.scheduler);
}

fn syscallCompletionInterrupt(_: *InterruptFrame) void {
    acknowledgeSyscallCompletionInterrupt();
}

pub inline fn acknowledgeSyscallCompletionInterrupt() void {
    x2apic.acknowledge();
}

test "prepared execution ISR records isolated prompts without claiming or preempting" {
    const ownership = @import("../../native/task/dispatch_ownership.zig");
    const Fixture = struct {
        var eois: [cpu_identity.MAX_CPUS]u32 = @splat(0);
        var hooks: usize = 0;
        var invalid_write = false;
        var expected_prompt = false;
        var reenter = false;
        var reentered = false;

        fn observe(msr: u32, value: u64) void {
            const cpu = cpu_identity.currentIndex();
            if (msr != x2apic.Testing.EOI_MSR or value != 0 or !interrupt_context.active()) invalid_write = true;
            eois[cpu] += 1;
            // The first hint must still be absent at EOI. Later deliveries may
            // find a coalesced hint; the real handler records it again afterward.
            const prompt = dispatch_transport.global.takePrompt(cpu) catch {
                invalid_write = true;
                return;
            };
            if (prompt != expected_prompt) invalid_write = true;
            if (reenter and !reentered) {
                reentered = true;
                var nested = std.mem.zeroes(Registers);
                nested.int_no = smp.PREPARED_EXECUTION_IPI_VECTOR;
                nested.cs = gdt.KERNEL_CODE_SEG;
                nested.eax = 0x1234_5678;
                const before = nested;
                isrHandler(&nested);
                if (!interrupt_context.active() or !std.meta.eql(before, nested)) invalid_write = true;
            }
        }
        fn hook(_: *InterruptFrame) void {
            hooks += 1;
        }
        fn takeOnly(cpu: u8) !void {
            const selected = cpu_identity.currentIndex();
            defer cpu_identity.setIndexForTest(selected);
            for (0..cpu_identity.MAX_CPUS) |index| {
                cpu_identity.setIndexForTest(@intCast(index));
                try std.testing.expectEqual(index == cpu, try dispatch_transport.global.takePrompt(@intCast(index)));
                try std.testing.expect(!try dispatch_transport.global.takePrompt(@intCast(index)));
            }
        }
        fn run(_: void) !void {
            eois = @splat(0);
            hooks = 0;
            invalid_write = false;
            reenter = false;
            reentered = false;
            setRuntimePreemption(hook);
            exception_handlers = @splat(hook);
            external_handlers = @splat(hook);
            try std.testing.expect(externalHandlerIndex(smp.PREPARED_EXECUTION_IPI_VECTOR) == null);
            try std.testing.expect(handlerForVector(smp.PREPARED_EXECUTION_IPI_VECTOR) == preparedExecutionInterrupt);

            var coordinator: ownership.Coordinator = .{};
            var tickets: [cpu_identity.MAX_CPUS]ownership.Ticket = undefined;
            var keys: [cpu_identity.MAX_CPUS]dispatch_transport.Key = undefined;
            cpu_identity.setIndexForTest(0);
            for (&tickets, &keys, 0..) |*ticket, *key, index| {
                const serial = @as(u64, @intCast(index)) + 1;
                ticket.* = try coordinator.prepare(@intCast(index), .{
                    .task_handle = serial,
                    .task_id = serial,
                    .process_generation = serial,
                    .address_space_id = serial,
                });
                try coordinator.bindPrepared(ticket.*, serial, serial * 4096);
                try dispatch_transport.global.publishInto(.{ .ticket = ticket.*, .trap_stack_top = 0x8000_0000 + @as(usize, index) * 4096 }, key);
            }
            const queued_before = dispatch_transport.global;
            const leases_before = coordinator;
            const pending_before = event_wake.peek();
            for (0..cpu_identity.MAX_CPUS) |index| {
                cpu_identity.setIndexForTest(@intCast(index));
                for ([_]usize{ gdt.KERNEL_CODE_SEG, gdt.USER_CODE_SEG | 3 }) |cs| {
                    var frame = std.mem.zeroes(Registers);
                    frame.int_no = smp.PREPARED_EXECUTION_IPI_VECTOR;
                    frame.cs = cs;
                    frame.eax = 0xface_9876;
                    frame.r15 = 0xfedc_ba98_7654_3210;
                    frame.eip = 0x4000_2000;
                    frame.eflags = 0x202;
                    const before = frame;
                    for (0..3) |delivery| {
                        expected_prompt = delivery != 0;
                        const previous_eois = eois[index];
                        isrHandler(&frame);
                        try std.testing.expectEqual(previous_eois + 1, eois[index]);
                        try std.testing.expectEqualDeep(before, frame);
                        try std.testing.expect(!interrupt_context.active());
                    }
                    try takeOnly(@intCast(index));
                    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&queued_before), std.mem.asBytes(&dispatch_transport.global));
                    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&leases_before), std.mem.asBytes(&coordinator));
                    try std.testing.expectEqual(pending_before, event_wake.peek());
                    try std.testing.expectEqual(@as(usize, 0), hooks);
                }
            }

            // A real nested dispatcher invocation balances its own context and
            // EOI while coalescing into the same owner-local prompt bit.
            cpu_identity.setIndexForTest(7);
            expected_prompt = false;
            reenter = true;
            const before_nested = eois[7];
            var frame = std.mem.zeroes(Registers);
            frame.int_no = smp.PREPARED_EXECUTION_IPI_VECTOR;
            frame.cs = gdt.USER_CODE_SEG | 3;
            isrHandler(&frame);
            try std.testing.expect(reentered and !interrupt_context.active());
            try std.testing.expectEqual(before_nested + 2, eois[7]);
            try takeOnly(7);
            try std.testing.expectEqualSlices(u8, std.mem.asBytes(&queued_before), std.mem.asBytes(&dispatch_transport.global));
            try std.testing.expectEqualSlices(u8, std.mem.asBytes(&leases_before), std.mem.asBytes(&coordinator));

            cpu_identity.setIndexForTest(0);
            for (tickets, keys) |ticket, key| {
                try dispatch_transport.global.withdraw(key);
                try coordinator.cancelUnstarted(ticket);
                var record: ownership.ReturnRecord = undefined;
                try coordinator.consumePreparedReturnInto(ticket, &record);
                var guard: dispatch_transport.Key = undefined;
                try std.testing.expect(try dispatch_transport.global.beginCollectionInto(ticket, &guard));
                _ = try coordinator.beginCollect(ticket);
                try coordinator.finishCollect(ticket);
                try dispatch_transport.global.finishCollection(guard);
            }
            const idle_before = dispatch_transport.global;
            const retired_before = coordinator;
            reenter = false;
            for (0..cpu_identity.MAX_CPUS) |index| {
                cpu_identity.setIndexForTest(@intCast(index));
                expected_prompt = false;
                frame.int_no = smp.PREPARED_EXECUTION_IPI_VECTOR;
                const previous_eois = eois[index];
                isrHandler(&frame);
                try std.testing.expectEqual(previous_eois + 1, eois[index]);
                try takeOnly(@intCast(index));
                var claimed: dispatch_transport.ClaimedCommand = .{ .key = keys[index], .command = .{ .ticket = tickets[index], .trap_stack_top = 0xdead_0000 } };
                const canary = claimed;
                try std.testing.expectError(error.NoCommand, dispatch_transport.global.claimInto(@intCast(index), &claimed));
                try std.testing.expectEqualDeep(canary, claimed);
                try std.testing.expectEqualSlices(u8, std.mem.asBytes(&idle_before), std.mem.asBytes(&dispatch_transport.global));
                try std.testing.expectEqualSlices(u8, std.mem.asBytes(&retired_before), std.mem.asBytes(&coordinator));
            }
            try std.testing.expect(!invalid_write);
            try std.testing.expectEqual(@as(usize, 0), hooks);
            try std.testing.expectEqual(pending_before, event_wake.peek());
        }
    };
    const previous_cpu = cpu_identity.currentIndex();
    const previous_pending = event_wake.take();
    const previous_pool = dispatch_transport.global;
    const previous_observer = x2apic.Testing.swapWriteObserver(Fixture.observe);
    defer {
        _ = x2apic.Testing.swapWriteObserver(previous_observer);
        dispatch_transport.global = previous_pool;
        cpu_identity.setIndexForTest(previous_cpu);
        _ = event_wake.take();
        inline for (std.meta.tags(event_wake.Kind)) |kind| {
            if (@as(u8, @bitCast(previous_pending)) & (@as(u8, 1) << @backingInt(kind)) != 0) event_wake.raise(kind);
        }
    }
    cpu_identity.setIndexForTest(0);
    dispatch_transport.global = .{};
    event_wake.raise(.network);
    event_wake.raise(.scheduler);
    try withTestHandlers({}, Fixture.run);
}

test "immutable broker vectors acknowledge once and wake only BSP user work" {
    const Fixture = struct {
        var eois: usize = 0;
        var hooks: usize = 0;
        var invalid_write = false;
        fn observe(msr: u32, value: u64) void {
            if (msr != x2apic.Testing.EOI_MSR or value != 0) invalid_write = true;
            eois += 1;
        }
        fn hook(_: *InterruptFrame) void {
            hooks += 1;
        }
        fn run(_: void) !void {
            setRuntimePreemption(hook);
            try std.testing.expect(externalHandlerIndex(smp.SYSCALL_REQUEST_IPI_VECTOR) == null);
            try std.testing.expect(externalHandlerIndex(smp.SYSCALL_COMPLETION_IPI_VECTOR) == null);
            for (0..cpu_identity.MAX_CPUS) |index| {
                cpu_identity.setIndexForTest(@intCast(index));
                for ([_]u8{ smp.SYSCALL_REQUEST_IPI_VECTOR, smp.SYSCALL_COMPLETION_IPI_VECTOR }) |vector| {
                    for ([_]usize{ gdt.KERNEL_CODE_SEG, gdt.USER_CODE_SEG | 3 }) |cs| {
                        _ = event_wake.take();
                        var frame = std.mem.zeroes(Registers);
                        frame.int_no = vector;
                        frame.cs = cs;
                        frame.eax = 0xFACE;
                        const before = frame;
                        const previous_eois = eois;
                        const previous_hooks = hooks;
                        isrHandler(&frame);
                        try std.testing.expectEqual(previous_eois + 1, eois);
                        const request_on_bsp = index == 0 and vector == smp.SYSCALL_REQUEST_IPI_VECTOR;
                        try std.testing.expectEqual(previous_hooks + @as(usize, if (request_on_bsp and cs & 3 == 3) 1 else 0), hooks);
                        try std.testing.expectEqual(event_wake.Pending{ .scheduler = request_on_bsp }, event_wake.peek());
                        try std.testing.expectEqualDeep(before, frame);
                        try std.testing.expect(!interrupt_context.active());
                    }
                }
            }
            try std.testing.expect(!invalid_write);
        }
    };
    const previous_cpu = cpu_identity.currentIndex();
    const previous_pending = event_wake.take();
    const previous_observer = x2apic.Testing.swapWriteObserver(Fixture.observe);
    defer {
        _ = x2apic.Testing.swapWriteObserver(previous_observer);
        cpu_identity.setIndexForTest(previous_cpu);
        _ = event_wake.take();
        inline for (std.meta.tags(event_wake.Kind)) |kind| {
            if (@as(u8, @bitCast(previous_pending)) & (@as(u8, 1) << @backingInt(kind)) != 0) event_wake.raise(kind);
        }
    }
    Fixture.eois = 0;
    Fixture.hooks = 0;
    Fixture.invalid_write = false;
    try withTestHandlers({}, Fixture.run);
}

fn spuriousInterrupt(_: *InterruptFrame) void {
    timer.handleSpuriousInterrupt();
}

fn interruptVector(regs: *const Registers) usize {
    const vector = std.math.cast(usize, regs.int_no) orelse unreachable;
    if (vector >= idt.IDT_ENTRIES) unreachable;
    return vector;
}

pub fn haltUnhandledException(regs: *const Registers) noreturn {
    const vector = interruptVector(regs);
    @call(.never_inline, console.print, .{"Received interrupt: "});
    if (vector < EXCEPTION_VECTOR_COUNT) {
        @call(.never_inline, console.print, .{exception_messages[vector]});
    } else {
        @call(.never_inline, console.print, .{"Unknown Interrupt"});
    }
    @call(.never_inline, console.print, .{"\nException context: vector=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, vector)});
    @call(.never_inline, console.print, .{" error=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.err_code)});
    @call(.never_inline, console.print, .{" rip=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.eip)});
    @call(.never_inline, console.print, .{" cs=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.cs)});
    @call(.never_inline, console.print, .{" rflags=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.eflags)});
    if (frameOriginatesFromUserspace(regs.cs)) {
        @call(.never_inline, console.print, .{" rsp=0x"});
        @call(.never_inline, numfmt.printHex, .{@as(u64, regs.useresp)});
        @call(.never_inline, console.print, .{" ss=0x"});
        @call(.never_inline, numfmt.printHex, .{@as(u64, regs.ss)});
    }
    @call(.never_inline, console.print, .{"\nSystem Halted!\n"});
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn reportInvalidInterruptReturn(regs: *const Registers) void {
    @call(.never_inline, console.print, .{"Rejected interrupt return: rip=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.eip)});
    @call(.never_inline, console.print, .{" cs=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.cs)});
    @call(.never_inline, console.print, .{" rflags=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.eflags)});
    @call(.never_inline, console.print, .{" rsp=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.useresp)});
    @call(.never_inline, console.print, .{" ss=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.ss)});
    @call(.never_inline, console.print, .{" user_data=0x"});
    @call(.never_inline, numfmt.printHex, .{gdt.userDataDescriptor()});
    @call(.never_inline, console.print, .{" user_code=0x"});
    @call(.never_inline, numfmt.printHex, .{gdt.userCodeDescriptor()});
    @call(.never_inline, console.print, .{"\n"});
}

fn frameOriginatesFromUserspace(code_selector: usize) bool {
    return code_selector & REQUESTED_PRIVILEGE_LEVEL_MASK == USER_PRIVILEGE_LEVEL;
}

fn setKernelGate(vector: u8, handler: GateHandler) void {
    idt.setGate(vector, handler, gdt.KERNEL_CODE_SEG, IDT_INTERRUPT_GATE);
}

fn disableLegacyPic() void {
    io.outb(PIC_MASTER_DATA_PORT, PIC_MASK_ALL);
    io.outb(PIC_SLAVE_DATA_PORT, PIC_MASK_ALL);
}

comptime {
    if (@sizeOf(@TypeOf(exception_handlers)) + @sizeOf(@TypeOf(external_handlers)) +
        @sizeOf(@TypeOf(runtime_preemption)) > HANDLER_STORAGE_SIZE_CEILING_BYTES)
    {
        @compileError("interrupt handler storage exceeds its compact size ceiling");
    }
    for (external_handler_vectors, 0..) |vector, index| {
        if (vector == smp.EXECUTION_STOP_IPI_VECTOR or vector == smp.SYSCALL_REQUEST_IPI_VECTOR or
            vector == smp.SYSCALL_COMPLETION_IPI_VECTOR or vector == smp.PREPARED_EXECUTION_IPI_VECTOR)
            @compileError("immutable execution vectors must not have mutable handler slots");
        if (vector < EXCEPTION_VECTOR_COUNT) {
            @compileError("external interrupt handler vector overlaps the exception table");
        }
        for (external_handler_vectors[0..index]) |prior_vector| {
            if (vector == prior_vector) @compileError("external interrupt handler vectors must be unique");
        }
    }
    if (@offsetOf(Registers, "int_no") != 136) {
        @compileError("x86-64 interrupt frame layout diverged from interrupt64.S");
    }
    if (@sizeOf(Registers) != 192) {
        @compileError("x86-64 interrupt frame size diverged from interrupt64.S");
    }
    if (frameOriginatesFromUserspace(gdt.KERNEL_CODE_SEG) or
        !frameOriginatesFromUserspace(gdt.USER_CODE_SEG | USER_PRIVILEGE_LEVEL))
    {
        @compileError("x86-64 interrupt privilege-origin decoding diverged from the GDT selectors");
    }
}

test "owned state ISR dispatches registered device-not-available and ordinary handlers" {
    const Handler = struct {
        var called: usize = 0;
        fn receive(frame: *InterruptFrame) void {
            if (!interrupt_context.active()) @panic("registered ISR handler has no interrupt context");
            called += 1;
            frame.eax = 0xfeed;
        }
    };
    const previous_handlers = exception_handlers;
    defer exception_handlers = previous_handlers;
    for ([_]u8{ 7, 13 }) |vector| {
        registerHandler(vector, Handler.receive);
        var frame = std.mem.zeroes(Registers);
        frame.int_no = vector;
        frame.cs = gdt.USER_CODE_SEG | USER_PRIVILEGE_LEVEL;
        frame.eip = 0x4000_1008;
        isrHandler(&frame);
        try std.testing.expectEqual(@as(usize, 0xfeed), frame.eax);
        try std.testing.expect(!interrupt_context.active());
    }
    try std.testing.expectEqual(@as(usize, 2), Handler.called);
}

const TimerIsrTest = if (@import("builtin").is_test) struct {
    var preemption_calls: [cpu_identity.MAX_CPUS]u32 = @splat(0);
    var preemption_ticks: [cpu_identity.MAX_CPUS]u64 = @splat(0);

    fn preempt(frame: *InterruptFrame) void {
        if (!interrupt_context.active() or frame.int_no != timer.INTERRUPT_VECTOR or
            !frameOriginatesFromUserspace(frame.cs))
            @panic("timer preemption must retain its userspace ISR context");
        const index = cpu_identity.currentIndex();
        preemption_calls[index] += 1;
        preemption_ticks[index] = timer.getTicks();
    }

    fn withHandler(model: *timer.Testing.Model, callback: anytype) !void {
        const saved_external = external_handlers;
        const saved_preemption = @atomicLoad(?InterruptHandler, &runtime_preemption, .acquire);
        const saved_calls = preemption_calls;
        const saved_ticks = preemption_ticks;
        const saved_wakes = event_wake.take();
        defer {
            external_handlers = saved_external;
            @atomicStore(?InterruptHandler, &runtime_preemption, saved_preemption, .release);
            preemption_calls = saved_calls;
            preemption_ticks = saved_ticks;
            _ = event_wake.take();
            inline for (.{ "timer", "xhci", "network", "nvme", "scheduler" }) |field| {
                if (@field(saved_wakes, field)) event_wake.raise(@field(event_wake.Kind, field));
            }
        }
        preemption_calls = @splat(0);
        preemption_ticks = @splat(0);
        registerHandler(timer.INTERRUPT_VECTOR, timerInterrupt);
        setRuntimePreemption(preempt);
        try callback(model);
    }

    fn counterBase(index: usize) u64 {
        return 1_000 + @as(u64, @intCast(index)) * 1_000;
    }

    fn initialize(model: *timer.Testing.Model) !void {
        const features = timer.Testing.deadline_features;
        for (0..cpu_identity.MAX_CPUS) |index| {
            cpu_identity.setIndexForTest(@intCast(index));
            // Only CPU 0 publishes epoch 1000. APs initialize at different
            // elapsed counters and must retain that common clock authority.
            model.cpus[index].now = counterBase(index);
            // Native interrupt-gate entry has IF clear before isrHandler.
            model.cpus[index].interrupts_enabled = false;
            if (index == 0) timer.init(features, .tsc_deadline) else try std.testing.expect(timer.initApplicationProcessor(features));
            timer.armSchedulerTick();
        }
    }

    fn dispatch(model: *timer.Testing.Model, code_selector: usize) !void {
        const index = cpu_identity.currentIndex();
        const eois_before = model.cpus[index].eois;
        var frame = std.mem.zeroes(Registers);
        frame.int_no = timer.INTERRUPT_VECTOR;
        frame.cs = code_selector;
        frame.eip = 0x4000_1008;
        frame.eax = 0x1122_3344;
        frame.r15 = 0x5566_7788;
        frame.eflags = 0x246;
        frame.useresp = 0x7fff_eff0;
        frame.ss = gdt.USER_DATA_SEG | USER_PRIVILEGE_LEVEL;
        const before = frame;
        isrHandler(&frame);
        try std.testing.expectEqualDeep(before, frame);
        try std.testing.expectEqual(eois_before + 1, model.cpus[index].eois);
        try std.testing.expect(!model.cpus[index].interrupts_enabled);
    }
} else struct {};

test "timer IRQ registered ISR services all CPUs and wakes only the BSP runtime owner" {
    const Case = struct {
        fn run(model: *timer.Testing.Model) !void {
            try TimerIsrTest.initialize(model);
            for (0..cpu_identity.MAX_CPUS) |index| {
                cpu_identity.setIndexForTest(@intCast(index));
                _ = event_wake.take();
                event_wake.raise(.network);
                event_wake.raise(.nvme);
                const expected = event_wake.Pending{
                    .network = true,
                    .nvme = true,
                    .timer = index == 0,
                    .scheduler = index == 0,
                };
                const tick_base = @as(u64, @intCast(index)) * 10;
                model.cpus[index].now = TimerIsrTest.counterBase(index) + 251;
                try TimerIsrTest.dispatch(model, gdt.KERNEL_CODE_SEG);
                try std.testing.expect(!interrupt_context.active());
                try std.testing.expectEqual(tick_base + 2, timer.getTicks());
                try std.testing.expectEqual(TimerIsrTest.counterBase(index) + 300, model.cpus[index].deadline);
                try std.testing.expectEqual(@as(u32, 0), TimerIsrTest.preemption_calls[index]);
                try std.testing.expectEqual(expected, event_wake.peek());

                for ([_]u64{ 399, 499 }, 0..) |elapsed, call_index| {
                    model.cpus[index].now = TimerIsrTest.counterBase(index) + elapsed;
                    try TimerIsrTest.dispatch(model, gdt.USER_CODE_SEG | USER_PRIVILEGE_LEVEL);
                    try std.testing.expect(!interrupt_context.active());
                    try std.testing.expectEqual(tick_base + call_index + 3, timer.getTicks());
                    try std.testing.expectEqual(TimerIsrTest.counterBase(index) + elapsed + 1, model.cpus[index].deadline);
                    try std.testing.expectEqual(@as(u32, @intCast(call_index + 1)), TimerIsrTest.preemption_calls[index]);
                    try std.testing.expectEqual(timer.getTicks(), TimerIsrTest.preemption_ticks[index]);
                    try std.testing.expectEqual(expected, event_wake.peek());
                }
            }
            for (0..cpu_identity.MAX_CPUS) |index| {
                cpu_identity.setIndexForTest(@intCast(index));
                try std.testing.expectEqual(@as(u64, @intCast(index)) * 10 + 4, timer.getTicks());
                try std.testing.expectEqual(TimerIsrTest.counterBase(index) + 500, model.cpus[index].deadline);
                try std.testing.expectEqual(@as(u32, 2), TimerIsrTest.preemption_calls[index]);
            }
        }
    };
    var model = timer.Testing.Model{};
    const snapshot = timer.Testing.install(&model);
    defer snapshot.restore();
    try TimerIsrTest.withHandler(&model, Case.run);
}

test "timer IRQ registered ISR preserves pending BSP work during foreign nested entries" {
    const Case = struct {
        fn run(model: *timer.Testing.Model) !void {
            try TimerIsrTest.initialize(model);
            cpu_identity.setIndexForTest(0);
            event_wake.raise(.xhci);
            model.cpus[0].now = 1_251;
            try TimerIsrTest.dispatch(model, gdt.KERNEL_CODE_SEG);
            const bsp_registers = model.cpus[0];
            const bsp_ticks = timer.getTicks();
            const pending = event_wake.peek();
            try std.testing.expectEqual(event_wake.Pending{ .timer = true, .scheduler = true, .xhci = true }, pending);

            interrupt_context.enter();
            defer {
                cpu_identity.setIndexForTest(0);
                interrupt_context.leave();
            }
            for (1..cpu_identity.MAX_CPUS) |index| {
                cpu_identity.setIndexForTest(@intCast(index));
                try std.testing.expect(!interrupt_context.active());
                interrupt_context.enter();
                defer {
                    cpu_identity.setIndexForTest(@intCast(index));
                    interrupt_context.leave();
                }
                const expected_ticks = @as(u64, @intCast(index)) * 10 + 3;
                model.cpus[index].now = TimerIsrTest.counterBase(index) + 351;
                try TimerIsrTest.dispatch(model, gdt.USER_CODE_SEG | USER_PRIVILEGE_LEVEL);
                try std.testing.expect(interrupt_context.active());
                try std.testing.expectEqual(expected_ticks, timer.getTicks());
                try std.testing.expectEqual(@as(u32, 1), TimerIsrTest.preemption_calls[index]);
                try std.testing.expectEqual(expected_ticks, TimerIsrTest.preemption_ticks[index]);
                try std.testing.expectEqual(pending, event_wake.peek());
                try std.testing.expectEqualDeep(bsp_registers, model.cpus[0]);
                cpu_identity.setIndexForTest(0);
                try std.testing.expect(interrupt_context.active());
                try std.testing.expectEqual(bsp_ticks, timer.getTicks());
                cpu_identity.setIndexForTest(@intCast(index));
            }
            cpu_identity.setIndexForTest(0);
            model.cpus[0].now = 1_499;
            try TimerIsrTest.dispatch(model, gdt.USER_CODE_SEG | USER_PRIVILEGE_LEVEL);
            try std.testing.expect(interrupt_context.active());
            try std.testing.expectEqual(@as(u32, 1), TimerIsrTest.preemption_calls[0]);
            try std.testing.expectEqual(@as(u64, 4), TimerIsrTest.preemption_ticks[0]);
            try std.testing.expectEqual(pending, event_wake.peek());
        }
    };
    var model = timer.Testing.Model{};
    const snapshot = timer.Testing.install(&model);
    defer snapshot.restore();
    try TimerIsrTest.withHandler(&model, Case.run);
    try std.testing.expect(!interrupt_context.active());
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        try std.testing.expect(!interrupt_context.active());
    }
}
