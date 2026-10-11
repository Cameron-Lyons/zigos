// Isolated architecture evidence: execute the production SIPI bridge and real
// per-CPU identity/GDT/TSS setup, then an isolated standard-XSAVE CPL0 IPI gate
// invokes the production TLB request handler. This does not admit production
// FRED, LASS, userspace entry or native trap ownership. The separate Mapping
// xstate root adds an explicitly admitted CPL0 compact-instruction phase.
const std = @import("std");
const x86 = @import("../x86.zig");
const address = @import("../kernel_address.zig");
const cpu_identity = @import("../../kernel/cpu_identity.zig");
const native_entry = @import("native_entry_state.zig");
const native_executor = @import("../../native/task/userspace_executor.zig");
const native_scheduler = @import("../../native/task/userspace_scheduler.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const abi = @import("../../native/core/abi.zig");
const object_ids = @import("../../native/core/ids.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const component_port = @import("../../native/kernel_api/component_port.zig");
const endpoint = @import("../../native/kernel_api/endpoint.zig");
const native_kernel = @import("../../native/kernel_api/native_kernel.zig");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const syscall_broker = @import("../../native/kernel_api/syscall_broker.zig");
const event_wake = @import("../../kernel/event_wake.zig");
const dispatch_ownership = @import("../../native/task/dispatch_ownership.zig");
const dispatch_transport = @import("../../native/task/dispatch_transport.zig");
const table_backing = @import("../../native/core/table_backing.zig");
const features = @import("../cpu_features.zig");
const gdt = @import("../../kernel/interrupts/gdt64.zig");
const syscall64 = @import("../../kernel/interrupts/syscall64.zig");
const idt = @import("../../kernel/interrupts/idt64.zig");
const isr = @import("../../kernel/interrupts/isr.zig");
const interrupt_context = @import("../../kernel/interrupts/context.zig");
const x2apic = @import("../../kernel/interrupts/x2apic.zig");
const paging = @import("../../kernel/memory/paging64.zig");
const paging_info = @import("../../boot/paging_info.zig");
const handoff = @import("../../kernel/boot/handoff.zig");
const early_console = @import("../../kernel/utils/console.zig");
const numfmt = @import("../../kernel/utils/numfmt.zig");
const table = @import("../../kernel/memory/page_table64.zig");
const layout = @import("../../kernel/memory/virtual_layout.zig");
const smp = @import("../../kernel/smp.zig");
const model = @import("../xstate_roundtrip_model.zig");
const xstate = @import("../xstate.zig");
const cache_policy = @import("../cache_policy.zig");
const bridge = @import("../../kernel/smp/trampoline.zig");
const tsc_clock = @import("../../kernel/timer/tsc_clock.zig");
const timer = @import("../../kernel/timer/timer.zig");
const proof = @import("high_half_probe.zig");

const PAGE_BYTES: usize = 4096;
const PROOF_CPU_COUNT: usize = 16;
const AP_ENTRY_CR4: usize = 0x40620; // PAE, OSFXSR, OSXMMEXCPT and OSXSAVE.
// The host harness pins this explicit emulator clock. QEMU need not advertise
// CPUID.15H, so this isolated timing contract is separate from CPU admission.
const PROOF_TSC_FREQUENCY_HZ: u64 = 2_400_000_000;
const WITNESS_ADDRESS = layout.device_memory.base + layout.device_memory.bytes - PAGE_BYTES;
const WITNESS_A: u64 = 0x1357_2468_aabb_ccdd;
const WITNESS_B: u64 = 0xfedc_ba98_1122_3344;
const DEVICE_WITNESS_ADDRESS = WITNESS_ADDRESS - 3 * PAGE_BYTES;
const DEVICE_PHYSICAL = [_]u64{ (1 << 30) - PAGE_BYTES, (512 << 20) - PAGE_BYTES };
const FLAG_DF: usize = 1 << 10;
const FLAG_AC: usize = 1 << 18;
const TRAP_PAINT_WORD: u32 = 0x57ac_c0de;
const TRAP_PAINT_DOUBLE: u64 = @as(u64, TRAP_PAINT_WORD) << 32 | TRAP_PAINT_WORD;
const TRAP_USABLE_PAGES = native_executor.TRAP_STACK_USABLE_BYTES / PAGE_BYTES;
const TIMER_LVT_MSR: u32 = 0x832;
const TIMER_INITIAL_COUNT_MSR: u32 = 0x838;
const TIMER_CURRENT_COUNT_MSR: u32 = 0x839;
const TSC_DEADLINE_MSR: u32 = 0x6e0;
const TIMER_MASKED: u64 = 1 << 16;
const BROKER_PAGE: usize = 0x400000;
const BROKER_REQUEST: usize = BROKER_PAGE + PAGE_BYTES - 16;
const BROKER_SEND_REQUEST: usize = BROKER_PAGE + PAGE_BYTES - 32;
const BROKER_PAYLOAD: usize = BROKER_PAGE + 2 * PAGE_BYTES - 44;
const BROKER_RECV_REQUEST: usize = BROKER_PAGE + PAGE_BYTES - 160;
const BROKER_CAPABILITY: usize = BROKER_PAGE + PAGE_BYTES - 32;
const BROKER_RESPONSE: usize = BROKER_PAGE + 3 * PAGE_BYTES - 24;
const BROKER_PRIVATE_BYTES: usize = 4 * PAGE_BYTES;
const BROKER_ROOT_FRAMES: usize = 8; // Root, three tables and four private leaves.
const BROKER_RECV_COPY_REQUEST: u32 = 3;
const BROKER_RECV_COPY_REPLY: u32 = 4;
const BROKER_RECV_MOVE_REQUEST: u32 = 5;
const BROKER_RECV_MOVE_REPLY: u32 = 6;
const BROKER_CLOSE_REQUEST: u32 = 7;
const BROKER_CLOSE_REPLY: u32 = 8;
const BROKER_TERMINATE_REQUEST: u32 = 9;
const BROKER_TERMINATE_REPLY: u32 = 10;
const BROKER_DONE: u32 = 11;
const PREPARED_OWNER_CPU: u8 = 1;
const PREPARED_OWNER_DONE: u32 = 4;
const PREPARED_TRANSPORT_DONE: u32 = 6;
const PREPARED_IPI_DONE: u32 = 6;
const TRAP_STACK_DONE: u32 = 4;
const TRAP_STACK_TOP_RESERVED: usize = 64;

comptime {
    // Each actual output crosses a different private 4 KiB leaf boundary.
    for ([_]struct { address: usize, bytes: usize }{
        .{ .address = BROKER_CAPABILITY, .bytes = @sizeOf(abi.CapabilityDescriptor) },
        .{ .address = BROKER_PAYLOAD, .bytes = abi.ENDPOINT_INLINE_BYTES },
        .{ .address = BROKER_RESPONSE, .bytes = @sizeOf(abi.EndpointRecvResponse) },
    }) |span| {
        if (span.address % PAGE_BYTES + span.bytes <= PAGE_BYTES or
            span.address + span.bytes > BROKER_PAGE + BROKER_PRIVATE_BYTES)
            @compileError("broker output fixture must cross a retained private leaf boundary");
    }
    if (PROOF_CPU_COUNT + 1 > task_runtime.MAX_TASK_CAPABILITIES or
        6 * (PROOF_CPU_COUNT - 1) + 1 > capability.MAX_CAPABILITIES)
        @compileError("broker copy/move fixture exceeds actual capability limits");
}

const BrokerReceipt = struct {
    response: abi.EndpointRecvResponse,
    capability: abi.CapabilityDescriptor,
};

const TimerObservation = struct {
    lvt: u64 = 0,
    initial_count: u64 = 0,
    current_count: u64 = 0,
    deadline: u64 = 0,
    cached_ticks: u64 = 0,
    deadline_supported: bool = false,
};

const Observation = struct {
    instruction: usize = 0,
    stack_pointer: usize = 0,
    physical_cr3: usize = 0,
    entry_cr4: usize = 0,
    gdt_base: usize = 0,
    tss_base: usize = 0,
    ring_stack_top: usize = 0,
    emergency_stack_top: usize = 0,
    gs_base: usize = 0,
    trap_stack_top: usize = 0,
    logical_cpu: u8 = 0,
    apic_id: u32 = 0,
    timer: TimerObservation = .{},
};

const CpuProof = struct {
    observation: Observation align(64) = .{},
    stack_guard: usize = 0,
    stack_top: usize = 0,
    trap_stack_top: usize = 0,
    status: u8 = 0,
    irq_ready: u32 = 0,
    irq_count: u32 = 0,
    irq_completed: u32 = 0,
    cache_ready: u32 = 0,
    cache_completed: u32 = 0,
    irq_environment_invalid: u8 = 0,
    continuation_cleared: u8 = 0,
    root_phase_completed: u32 = 0,
    stop_count: u32 = 0,
    stop_completed: u32 = 0,
    stop_observations: u8 = 0,
    stop_environment_invalid: u8 = 0,
    timer_checked: u8 = 0,
    cold_stack_checked: u8 = 0,
    broker_published: u8 = 0,
    broker_consumed: u8 = 0,
    broker_ipc_published: u8 = 0,
    broker_ipc_consumed: u8 = 0,
    broker_recv_published: u32 = 0,
    broker_recv_consumed: u32 = 0,
    broker_close_published: u8 = 0,
    broker_close_consumed: u8 = 0,
    broker_returned: u8 = 0,
    broker_stop_count: u32 = 0,
    broker_completion_count: u32 = 0,
    broker_tlb_count: u32 = 0,
    seed: model.Image = undefined,
    restored: model.Image = undefined,
};

var cpus: [PROOF_CPU_COUNT]CpuProof = @splat(.{});
var physical_cr3: usize = 0;
var startup_physical: u32 = 0;
var irq_phase: u32 = 0;
var cache_phase: u32 = 0;
var cache_publication: u32 = 0;
var continuation_clear_target: u8 = std.math.maxInt(u8);
var root_phase: u32 = 0;
var timer_check_target: u8 = std.math.maxInt(u8);
var private_roots: [PROOF_CPU_COUNT - 1]paging.UserAddressSpace = undefined;
var dispatch_runtime: ?*task_runtime.Runtime = null;
var dispatch_tickets: [PROOF_CPU_COUNT - 1]dispatch_ownership.Ticket = undefined;
var dispatch_task_ids: [PROOF_CPU_COUNT - 1]u64 = undefined;
var dispatch_address_ids: [PROOF_CPU_COUNT - 1]u64 = undefined;
var dispatch_return_target: u8 = std.math.maxInt(u8);
var dispatch_collection_target: u8 = std.math.maxInt(u8);
var dispatch_task_retirements: u8 = 0;
var dispatch_root_retirements: u8 = 0;
var dispatch_stop_notifications: u8 = 0;
var broker_phase: u32 = 0;
var broker_request_count: u32 = 0;
var broker_mapping_handles: [PROOF_CPU_COUNT]native_executor.MappingHandle = undefined;
var broker_expected_receipts: [2][PROOF_CPU_COUNT - 1]BrokerReceipt = undefined;

// The AP returns ownership before the BSP can collect its Runtime pin. Keep
// commands, callback expectations and completion storage outside that domain;
// even the deliberately stale retry must not consult freed fixture metadata.
const PreparedOwnerExpectation = struct {
    task_id: u64 = 0,
    physical_root: u64 = 0,
    user_context: native_executor.UserContext64 = .{},
    receipt: dispatch_ownership.ReturnRecord = .{},
};
var prepared_command: native_executor.ArchitecturePreparedCommand = undefined;
var prepared_stale_command: native_executor.ArchitecturePreparedCommand = undefined;
var prepared_owner_source: ?*native_executor.Executor = null;
var prepared_owner_expectation: PreparedOwnerExpectation = .{};
var prepared_phase: u32 = 0;
var prepared_completed: u32 = 0;
var prepared_owner_ran: bool = false;
var prepared_callback_count: u32 = 0;
var prepared_xstate_address: usize = 0;
var prepared_neighbors: [PROOF_CPU_COUNT]native_entry.State = undefined;

// This independent storage outlives every queued lease/domain. In particular,
// the post-ACK hook accesses only these phase words before static completion.
var transport_phase: u32 = 0;
var transport_claimed: u32 = 0;
var transport_returned: u32 = 0;
var transport_released: u32 = 0;
var transport_completed: u32 = 0;
var transport_owner_phase: u32 = 0;
var transport_owner_ran: bool = false;
var transport_key: dispatch_transport.Key = undefined;
var transport_stale_key: dispatch_transport.Key = undefined;
var transport_claim_canary: dispatch_transport.ClaimedCommand = undefined;

// Fixed-vector delivery is only a hint. These permanent receipts are observed
// after IRET before the owner invokes the exact queue claim/runner protocol.
var prompted_phase: u32 = 0;
var prompted_checked: u32 = 0;
var prompted_returned: u32 = 0;
var prompted_released: u32 = 0;
var prompted_completed: u32 = 0;
var prompted_owner_phase: u32 = 0;
var prompted_owner_ran: bool = false;
var prompted_ipi_count: u32 = 0;
var prompted_key: dispatch_transport.Key = undefined;
pub export var zigos_arch_smp_prepared_ipi_window: u32 = 0;

// Permanent phase/receipt storage outlives the queued domain and its ACK.
// The production ISR owns the prompt; no proof handler seeds a replacement.
var trap_stack_phase: u32 = 0;
var trap_stack_quiescent: [PROOF_CPU_COUNT]u8 = @splat(0);
var trap_stack_checked: u32 = 0;
var trap_stack_returned: u32 = 0;
var trap_stack_released: u32 = 0;
var trap_stack_completed: u32 = 0;
var trap_stack_owner_ran: bool = false;
var trap_stack_baseline_low: usize = 0;
var trap_stack_interrupt_low: usize = 0;
var trap_stack_key: dispatch_transport.Key = undefined;
pub export var zigos_arch_smp_trap_ipi_window: u32 = 0;

const DispatchRetirement = struct {
    fn notifyStop(_: *anyopaque, ticket: task_runtime.ExecutionTicket) void {
        const runtime = dispatch_runtime orelse proof.fail("SMP stop notification runtime");
        if (cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or
            ticket.cpu == 0 or ticket.cpu >= PROOF_CPU_COUNT) proof.fail("SMP stop notification owner");
        const expected = dispatch_tickets[ticket.cpu - 1];
        if (ticket.issuer != &runtime.execution or ticket.issuer != expected.issuer or
            ticket.epoch != expected.epoch or
            (runtime.execution.phase(ticket) catch proof.fail("SMP stop notification ticket")) != .running or
            !smp.notifyExecutionStop(ticket.cpu)) proof.fail("SMP stop notification transport");
        dispatch_stop_notifications += 1;
    }

    fn retire(_: *anyopaque, event: task_runtime.TaskRetirement) void {
        const runtime = dispatch_runtime orelse proof.fail("SMP dispatch retirement runtime");
        const cpu = dispatch_collection_target;
        if (cpu == 0 or cpu >= PROOF_CPU_COUNT or cpu_identity.currentIndex() != 0 or x86.interruptsEnabled())
            proof.fail("SMP dispatch retirement owner");
        const index = cpu - 1;
        const task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP dispatch retained task");
        if (event.task_id != task.id or event.now_ticks != 100 + @as(u64, cpu) or task.state != .terminated or
            event.capability_ids.len != 1 or event.capability_ids[0] != 700 + @as(u64, cpu) or
            task.capability_count != 1 or task.execution_component_count != 1 or
            runtime.findAddressSpaceConst(dispatch_address_ids[index]) == null or
            !runtime.execution.hasLeaseForTask(task.id)) proof.fail("SMP dispatch early task resources");
        dispatch_task_retirements += 1;
    }

    pub fn retireAddressSpace(_: *@This(), event: task_runtime.AddressSpaceRetirementEvent) void {
        const runtime = dispatch_runtime orelse proof.fail("SMP dispatch root runtime");
        const cpu = dispatch_collection_target;
        if (cpu == 0 or cpu >= PROOF_CPU_COUNT or cpu_identity.currentIndex() != 0 or x86.interruptsEnabled())
            proof.fail("SMP dispatch root retirement owner");
        const index = cpu - 1;
        const task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP dispatch root task");
        if (event.address_space_id != dispatch_address_ids[index] or event.reason != .terminate or
            runtime.findAddressSpaceConst(event.address_space_id) != null or task.capability_count != 0 or
            task.execution_component_count != 0 or !runtime.execution.hasLeaseForTask(task.id) or
            @atomicLoad(u32, &cpus[cpu].root_phase_completed, .acquire) != 2)
            proof.fail("SMP dispatch root before acknowledged resources");
        paging.destroyUserAddressSpace(&private_roots[index]) catch proof.fail("SMP dispatch acknowledged root release");
        dispatch_root_retirements += 1;
    }
};

extern var stack_bottom: u8;
extern var stack_top: u8;
extern fn zigos_arch_smp_tlb_ipi() callconv(.c) void;
extern fn zigos_arch_smp_execution_stop_ipi() callconv(.c) void;
extern fn zigos_arch_smp_syscall_request_ipi() callconv(.c) void;
extern fn zigos_arch_smp_syscall_completion_ipi() callconv(.c) void;
extern fn zigos_arch_smp_prepared_execution_ipi() callconv(.c) void;
extern fn zigos_arch_smp_spurious_ipi() callconv(.c) void;
extern fn zigos_arch_smp_wait_for_ipi(*const model.Image, *model.Image, *usize) callconv(.c) u64;
extern fn zigos_arch_smp_poll_for_ipi(*const model.Image, *model.Image, *usize) callconv(.c) u64;
extern fn zigos_arch_smp_poll_prepared_ipi(*const model.Image, *model.Image, *usize) callconv(.c) u64;
extern fn zigos_arch_smp_poll_trap_stack(*const model.Image, *model.Image, *usize, usize) callconv(.c) u64;
extern fn isr116() callconv(.c) void;

// The isolated memory fixture must carry the actual small allocations rather
// than maximum-capacity reservations. This reads receipts before the final
// hierarchy exists and does not use its later per-CPU root tracker.
pub fn proveBootArenaSizing(transition_cr3: u64) void {
    const info = handoff.capturedInfo() orelse proof.fail("initial arena handoff");
    const arenas = info.boot_paging orelse proof.fail("initial arena receipts");
    arenas.validate() catch proof.fail("initial arena receipt bounds");
    if (transition_cr3 != arenas.transition_base or
        arenas.transition_pages == paging_info.MAX_ARENA_PAGES or
        arenas.final_pages == paging_info.MAX_ARENA_PAGES) proof.fail("initial small arena allocation");
    early_console.print("Boot paging arena allocations: transition=");
    numfmt.printDec(arenas.transition_pages);
    early_console.print(" final=");
    numfmt.printDec(arenas.final_pages);
    early_console.print(" pages\n");
    proof.pass("BOOT_ARENA_SIZING");
}

// Boot-exclusive evidence, before AP startup or any ordinary frame allocation.
// The transition arena has no remaining table reader after verified CR3/global
// retirement. Every table emitted by the sparse builder is in its live prefix.
pub fn proveBootArenaReclamation(final_cr3: u64, instruction: usize, anchor: usize) void {
    if (x86.interruptsEnabled() or !paging.kernelAddressSpaceActive()) proof.fail("boot arena proof context");
    const info = handoff.capturedInfo() orelse proof.fail("boot arena handoff");
    const arenas = info.boot_paging orelse proof.fail("boot arena receipts");
    const retired = paging.bootPagingArenaRetirement();
    if (retired.used_pages < 3 or retired.used_pages > arenas.final_pages or
        final_cr3 != arenas.final_base) proof.fail("boot arena retained prefix");
    const prefix_end = arenas.final_base + @as(u64, retired.used_pages) * PAGE_BYTES;
    const ranges = [_]paging.FrameRun{
        .{ .base = arenas.transition_base, .count = arenas.transition_pages },
        .{ .base = prefix_end, .count = arenas.final_pages - retired.used_pages },
    };
    const recovered = ranges[0].count + ranges[1].count;
    const initial = paging.frameStats();
    if (retired.reclaimed_pages != recovered or initial.allocated != 0 or
        retired.reserved_before > initial.total or retired.reserved_before < recovered or
        initial.reserved != retired.reserved_before - recovered or
        initial.free != initial.total - retired.reserved_before + recovered)
        proof.fail("boot arena exact recovery accounting");
    if (paging.allocGeneralFramesBetween(1, arenas.final_base, prefix_end) != null or
        !std.meta.eql(initial, paging.frameStats())) proof.fail("boot arena live tables allocated");
    const before = bootArenaPrefixFingerprint(arenas.final_base, retired.used_pages);
    var held: [2]paging.FrameRun = undefined;
    var held_count: usize = 0;
    for (ranges, 0..) |range, index| {
        if (range.count == 0) continue;
        const end = range.base + @as(u64, range.count) * PAGE_BYTES;
        const frames = paging.allocGeneralFramesBetween(range.count, range.base, end) orelse proof.fail("boot arena complete reuse");
        if (!std.meta.eql(range, frames)) proof.fail("boot arena reuse escaped receipt");
        held[held_count] = frames;
        held_count += 1;
        const first = arenaReuseWord(frames.base);
        const last = arenaReuseWord(end - @sizeOf(u64));
        const pattern = 0x6172_656e_612d_0000 | @as(u64, @intCast(index));
        first.* = pattern;
        last.* = ~pattern;
        if (first.* != pattern or last.* != ~pattern) proof.fail("boot arena reclaimed RAM write");
    }
    const allocated = paging.frameStats();
    if (allocated.total != initial.total or allocated.reserved != initial.reserved or
        allocated.allocated != recovered or allocated.free != initial.free - recovered)
        proof.fail("boot arena exact reuse accounting");
    for (held[0..held_count]) |frames|
        paging.releaseGeneralFrames(frames) catch proof.fail("boot arena reused frame release");
    if (!std.meta.eql(initial, paging.frameStats()) or
        bootArenaPrefixFingerprint(arenas.final_base, retired.used_pages) != before or
        x86.readCr3() & x86.CR3_ADDRESS_MASK != final_cr3 or !paging.kernelAddressSpaceActive())
        proof.fail("boot arena live hierarchy or accounting changed");
    const image = readLeaf(instruction) orelse proof.fail("boot arena image mapping");
    const data = readLeaf(anchor) orelse proof.fail("boot arena data mapping");
    if (image.physical(instruction) != address.imagePhysicalAddress(instruction).? or
        image.entry & (table.WRITABLE | table.USER | table.NO_EXECUTE) != 0 or
        data.physical(anchor) != address.imagePhysicalAddress(anchor).? or
        data.entry & (table.WRITABLE | table.NO_EXECUTE | table.USER) != table.WRITABLE | table.NO_EXECUTE)
        proof.fail("boot arena image mappings changed");
    early_console.print("Boot paging arena pages: retained=");
    numfmt.printDec(retired.used_pages);
    early_console.print(" reclaimed=");
    numfmt.printDec(retired.reclaimed_pages);
    early_console.print("\n");
    proof.pass("BOOT_ARENA_RECLAIM");
}

fn arenaReuseWord(physical: u64) *volatile u64 {
    const virtual = paging.directMapAddress(physical) orelse proof.fail("boot arena reuse alias");
    const leaf = readLeaf(virtual) orelse proof.fail("boot arena reuse mapping");
    const pat_bit: u64 = if (leaf.shift == table.PAGE_TABLE_SHIFT) 1 << 7 else 1 << 12;
    if (leaf.physical(virtual) != physical or
        leaf.entry & (table.WRITABLE | table.USER | table.NO_EXECUTE) != table.WRITABLE | table.NO_EXECUTE or
        leaf.entry & (table.WRITE_THROUGH | table.CACHE_DISABLE | pat_bit) != 0)
        proof.fail("boot arena reuse WB supervisor permissions");
    return @ptrFromInt(virtual);
}

fn bootArenaPrefixFingerprint(physical: u64, pages: u32) u64 {
    var fingerprint: u64 = 0xcbf2_9ce4_8422_2325;
    for (0..@as(usize, pages)) |page| {
        const alias = paging.directMapAddress(physical + page * PAGE_BYTES) orelse proof.fail("boot arena live table alias");
        const words: *const volatile table.Table = @ptrFromInt(alias);
        for (0..table.TABLE_ENTRIES) |index| {
            // Hardware may set A/D while the proof reads or writes RAM aliases;
            // every address, ownership and permission bit must stay unchanged.
            fingerprint = (fingerprint ^ (words[index] & ~@as(u64, (1 << 5) | (1 << 6)))) *% 0x100_0000_01b3;
        }
    }
    return fingerprint;
}

pub fn run() void {
    if (cpu_identity.MAX_CPUS != PROOF_CPU_COUNT) proof.fail("SMP configured CPU bound");
    const bsp_features = features.detect();
    if (!bsp_features.rdpid or !bsp_features.x2apic or !bsp_features.smap or !bsp_features.pge) proof.fail("SMP architecture support");
    if (x86.interruptsEnabled() or !paging.kernelAddressSpaceActive()) proof.fail("SMP BSP state");
    tsc_clock.init(PROOF_TSC_FREQUENCY_HZ);
    x2apic.enable();
    // Exercise the actual timer authority using this fixture's explicit clock.
    // Countdown initialization retains its modeled periodic BSP behavior; mask
    // and stop that source before the isolated IPI gates ever enable IF.
    var timer_features = bsp_features;
    timer_features.tsc_frequency_hz = PROOF_TSC_FREQUENCY_HZ;
    timer.init(timer_features, .calibrated_countdown);
    x86.writeMsr(TIMER_LVT_MSR, TIMER_MASKED | timer.INTERRUPT_VECTOR);
    x86.writeMsr(TIMER_INITIAL_COUNT_MSR, 0);
    if (bsp_features.tsc_deadline) x86.writeMsr(TSC_DEADLINE_MSR, 0);
    // Only the isolated fixed TLB/stop gates may enable IF. The spurious
    // vector has a register-preserving IRET gate and no EOI.
    x86.outb(0x21, 0xff);
    x86.outb(0xa1, 0xff);
    idt.setGate(smp.TLB_IPI_VECTOR, &zigos_arch_smp_tlb_ipi, gdt.KERNEL_CODE_SEG, 0x8e);
    idt.setGate(smp.EXECUTION_STOP_IPI_VECTOR, &zigos_arch_smp_execution_stop_ipi, gdt.KERNEL_CODE_SEG, 0x8e);
    idt.setGate(smp.SYSCALL_REQUEST_IPI_VECTOR, &zigos_arch_smp_syscall_request_ipi, gdt.KERNEL_CODE_SEG, 0x8e);
    idt.setGate(smp.SYSCALL_COMPLETION_IPI_VECTOR, &zigos_arch_smp_syscall_completion_ipi, gdt.KERNEL_CODE_SEG, 0x8e);
    idt.setGate(smp.PREPARED_EXECUTION_IPI_VECTOR, &zigos_arch_smp_prepared_execution_ipi, gdt.KERNEL_CODE_SEG, 0x8e);
    idt.setGate(x2apic.SPURIOUS_VECTOR, &zigos_arch_smp_spurious_ipi, gdt.KERNEL_CODE_SEG, 0x8e);
    idt.init();
    maskLocalInterruptSources();
    if (x2apic.localId() != 0) proof.fail("SMP explicit topology BSP");
    physical_cr3 = x86.readCr3() & x86.CR3_ADDRESS_MASK;
    // Provision on the BSP while every native-entry slot is inactive. These
    // allocations remain retained until emulator exit. CPU 1 verifies a cold
    // TSS/GS stack binding and later uses manual CPL0 RSP; neither fixture
    // publishes ENTRY_READY or enters through a native privilege transition.
    provisionTrapStacks();
    cpus[0].stack_guard = @intFromPtr(&stack_bottom);
    cpus[0].stack_top = @intFromPtr(&stack_top);
    touchSelectedTrapStack(0);
    bindProofContinuation(0);
    cpus[0].observation = observe(0, x86.readCr4()) orelse proof.fail("SMP BSP descriptors");
    cpus[0].observation.timer = observeTimer(bsp_features.tsc_deadline);
    @atomicStore(u8, &cpus[0].status, 1, .release);

    const trampoline = bridge.install() orelse proof.fail("SMP bridge installation");
    startup_physical = trampoline.physical;
    paging.mapKernelBorrowedPage(startup_physical, startup_physical, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_EXECUTABLE);
    for (1..PROOF_CPU_COUNT) |index| {
        const stack = bridge.allocateStack() orelse proof.fail("SMP AP stack allocation");
        cpus[index].stack_guard = stack.guard;
        cpus[index].stack_top = stack.top;
        if (!bridge.patch(trampoline, @intCast(index), cpus[index].stack_top, &apEntry)) proof.fail("SMP bridge patch");
        // This harness uses one socket, sixteen cores and one thread per core:
        // QEMU's contiguous APIC IDs are checked again on every admitted AP.
        x2apic.sendInit(@intCast(index));
        waitMilliseconds(10);
        const vector: u8 = @intCast(startup_physical / PAGE_BYTES);
        x2apic.sendStartup(@intCast(index), vector);
        waitMilliseconds(1);
        if (@atomicLoad(u8, &cpus[index].status, .acquire) == 0) {
            x2apic.sendStartup(@intCast(index), vector);
        }
        const deadline = tsc_clock.afterMilliseconds(2000);
        while (@atomicLoad(u8, &cpus[index].status, .acquire) == 0) {
            if (deadline.expired()) proof.fail("SMP AP completion timeout");
            asm volatile ("pause");
        }
        if (@atomicLoad(u8, &cpus[index].status, .acquire) != 1) proof.fail("SMP AP observation");
    }

    for (&cpus) |*cpu| {
        if (@atomicLoad(u8, &cpu.status, .acquire) != 1 or
            cpu.observation.physical_cr3 != physical_cr3 or
            address.imagePhysicalAddress(cpu.observation.instruction) == null or
            cpu.observation.stack_pointer <= cpu.stack_guard + PAGE_BYTES or
            cpu.observation.stack_pointer >= cpu.stack_top) proof.fail("SMP high entry or stack");
    }
    proof.pass("SMP_16_ENTRY");
    for (cpus[1..]) |*cpu| {
        if (cpu.observation.entry_cr4 != AP_ENTRY_CR4) proof.fail("SMP minimal transition controls");
    }
    proof.pass("SMP_16_CONTROLS");
    // Each AP adopted and verified the complete immutable BSP cache policy
    // before publication. Enabled MTRRs are compared without writes; disabled
    // policies receive the production initialization and readback sequence.
    proof.pass("SMP_16_CACHE_POLICY");
    for (&cpus, 0..) |*cpu, index| {
        if (cpu.observation.logical_cpu != index or cpu.observation.apic_id != index) proof.fail("SMP logical identity");
    }
    proof.pass("SMP_16_IDENTITY");
    proveTimers();
    if (@atomicLoad(u8, &cpus[PREPARED_OWNER_CPU].cold_stack_checked, .acquire) != 1)
        proof.fail("SMP cold stack ownership receipt");
    for (&cpus, 0..) |*cpu, index| {
        const emergency_guard = gdt.doubleFaultStackGuardAddressForCpu(@intCast(index));
        if (cpu.observation.ring_stack_top != cpu.stack_top or
            cpu.observation.emergency_stack_top != emergency_guard + gdt.DOUBLE_FAULT_STACK_TOTAL_BYTES or
            paging.currentPagePermissions(emergency_guard) != null or
            paging.currentPagePermissions(cpu.stack_guard) != null) proof.fail("SMP guarded stack ownership");
        const emergency = paging.currentPagePermissions(emergency_guard + PAGE_BYTES) orelse proof.fail("SMP emergency stack mapping");
        if (emergency.user or !emergency.writable or emergency.executable) proof.fail("SMP emergency stack permissions");
        if (index != 0) {
            var usable = cpu.stack_guard + PAGE_BYTES;
            while (usable < cpu.stack_top) : (usable += PAGE_BYTES) {
                const permissions = paging.currentPagePermissions(usable) orelse proof.fail("SMP AP usable stack mapping");
                if (permissions.user or !permissions.writable or permissions.executable) proof.fail("SMP AP usable stack permissions");
            }
            if (cpu.stack_top - cpu.stack_guard - PAGE_BYTES != bridge.STACK_USABLE_BYTES or
                cpu.stack_top % x86.FRED_STACK_ALIGNMENT != 0) proof.fail("SMP AP stack capacity");
        }
        for (cpus[0..index]) |*earlier| {
            if (cpu.observation.gdt_base == earlier.observation.gdt_base or
                cpu.observation.tss_base == earlier.observation.tss_base or
                cpu.stack_top == earlier.stack_top or
                cpu.observation.emergency_stack_top == earlier.observation.emergency_stack_top) proof.fail("SMP descriptor alias");
        }
    }
    proof.pass("SMP_16_DESCRIPTORS");
    proveTrapStacks();
    proveContinuations();
    var ids: [PROOF_CPU_COUNT]u32 = undefined;
    for (&cpus, &ids) |*cpu, *apic_id| apic_id.* = cpu.observation.apic_id;
    smp.ArchitectureProof.bindTopology(&ids);
    proveCurrentRoots();
    if (!paging.unmapBorrowedCurrentPage(startup_physical) or
        paging.currentPagePermissions(startup_physical) != null) proof.fail("SMP lower bridge retirement");
    proof.pass("SMP_LOW_RETIRED");
    runGlobalTlbProof();
}

fn observeTimer(deadline_supported: bool) TimerObservation {
    return .{
        .lvt = x86.readMsr(TIMER_LVT_MSR),
        .initial_count = x86.readMsr(TIMER_INITIAL_COUNT_MSR),
        .current_count = x86.readMsr(TIMER_CURRENT_COUNT_MSR),
        .deadline = if (deadline_supported) x86.readMsr(TSC_DEADLINE_MSR) else 0,
        .cached_ticks = timer.getTicks(),
        .deadline_supported = deadline_supported,
    };
}

fn timerDisarmed(observation: *const TimerObservation) bool {
    return observation.lvt == TIMER_MASKED | timer.INTERRUPT_VECTOR and
        observation.initial_count == 0 and observation.current_count == 0 and observation.deadline == 0;
}

fn proveTimers() void {
    const bsp = &cpus[0].observation.timer;
    if (!timerDisarmed(bsp) or timer.getTicks() != bsp.cached_ticks or
        cpus[PROOF_CPU_COUNT - 1].observation.timer.cached_ticks <= cpus[1].observation.timer.cached_ticks)
        proof.fail("SMP timer BSP cache or staggered clock");
    for (cpus[1..]) |*cpu| {
        if (!timerDisarmed(&cpu.observation.timer) or cpu.observation.timer.cached_ticks <= bsp.cached_ticks)
            proof.fail("SMP timer AP disarmed registers");
    }
    // Later APs have synchronized their own caches. Revisit opposite ends in
    // turn; each AP must still read its own earlier value through real RDPID
    // selection. No timer interrupt or unsupported deadline instruction runs.
    for (0..PROOF_CPU_COUNT - 1) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) PROOF_CPU_COUNT - 1 - position / 2 else 1 + position / 2);
        @atomicStore(u8, &timer_check_target, index, .release);
        const deadline = tsc_clock.afterMilliseconds(2000);
        while (@atomicLoad(u8, &cpus[index].timer_checked, .acquire) != 1) {
            if (@atomicLoad(u8, &cpus[index].status, .acquire) != 1 or deadline.expired())
                proof.fail("SMP timer selected cache isolation");
            asm volatile ("pause");
        }
        const current_bsp = observeTimer(bsp.deadline_supported);
        if (current_bsp.cached_ticks != bsp.cached_ticks or !timerDisarmed(&current_bsp))
            proof.fail("SMP timer BSP changed by peer");
    }
    proof.pass("SMP_16_TIMERS");
}

fn checkOwnTimer(index: u8) void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    while (@atomicLoad(u8, &timer_check_target, .acquire) != index) {
        if (deadline.expired()) reject(index);
        asm volatile ("pause");
    }
    const observed = observeTimer(cpus[index].observation.timer.deadline_supported);
    if (x86.interruptsEnabled() or cpu_identity.currentIndex() != index or
        !timerDisarmed(&observed) or observed.cached_ticks != cpus[index].observation.timer.cached_ticks)
        reject(index);
    @atomicStore(u8, &cpus[index].timer_checked, 1, .release);
}

fn provisionTrapStacks() void {
    if (TRAP_USABLE_PAGES != 9 or native_executor.TRAP_STACK_TOTAL_BYTES != 10 * PAGE_BYTES)
        proof.fail("SMP trap stack geometry contract");
    for (&cpus, 0..) |*cpu, index| {
        const logical: u8 = @intCast(index);
        if (native_executor.preparedKernelStackForCpu(logical) != null) proof.fail("SMP trap stack already provisioned");
        native_executor.reserveTrapStackStorageForCpu(logical) catch proof.fail("SMP trap stack provision");
        cpu.trap_stack_top = native_executor.preparedKernelStackForCpu(logical) orelse proof.fail("SMP trap stack publication");
    }
    verifyTrapStackGeometry();
    for (&cpus) |*cpu| {
        var cursor = cpu.trap_stack_top - native_executor.TRAP_STACK_USABLE_BYTES;
        while (cursor < cpu.trap_stack_top) : (cursor += @sizeOf(u32)) {
            const word: *const volatile u32 = @ptrFromInt(cursor);
            if (word.* != TRAP_PAINT_WORD) proof.fail("SMP complete trap stack paint");
        }
    }
    // Seed one slot at a time and inspect every neighbor, including slots that
    // still contain only the allocator's initial paint.
    for (&cpus, 0..) |*cpu, index| {
        trapStackWord(cpu.trap_stack_top, false).* = trapStackCanary(@intCast(index), false, false);
        trapStackWord(cpu.trap_stack_top, true).* = trapStackCanary(@intCast(index), true, false);
        for (&cpus, 0..) |*neighbor, other| {
            for ([_]bool{ false, true }) |last| {
                const expected = if (other <= index) trapStackCanary(@intCast(other), last, false) else TRAP_PAINT_DOUBLE;
                if (trapStackWord(neighbor.trap_stack_top, last).* != expected) proof.fail("SMP trap stack provision neighbor");
            }
        }
    }
}

fn verifyTrapStackGeometry() void {
    var physical_pages: [PROOF_CPU_COUNT * TRAP_USABLE_PAGES]u64 = undefined;
    var physical_count: usize = 0;
    for (&cpus, 0..) |*cpu, index| {
        const top = cpu.trap_stack_top;
        if (!@import("../cpu_baseline.zig").isCanonicalUpperHalf(top) or
            top % PAGE_BYTES != 0 or top % x86.FRED_STACK_ALIGNMENT != 0) proof.fail("SMP trap stack top geometry");
        const guard = top - native_executor.TRAP_STACK_TOTAL_BYTES;
        if (paging.currentPagePermissions(guard) != null or
            native_executor.preparedKernelStackForCpu(@intCast(index)) != top) proof.fail("SMP trap stack guard or ownership");
        for (cpus[0..index]) |*earlier| {
            const earlier_guard = earlier.trap_stack_top - native_executor.TRAP_STACK_TOTAL_BYTES;
            if (guard < earlier.trap_stack_top and earlier_guard < top) proof.fail("SMP trap stack range overlap");
        }
        var page = guard + PAGE_BYTES;
        while (page < top) : (page += PAGE_BYTES) {
            const permissions = paging.currentPagePermissions(page) orelse proof.fail("SMP trap usable leaf");
            if (permissions.user or !permissions.writable or permissions.executable) proof.fail("SMP trap usable permissions");
            const physical = trapStackPagePhysical(page);
            for (physical_pages[0..physical_count]) |earlier| {
                if (physical == earlier) proof.fail("SMP trap physical backing alias");
            }
            physical_pages[physical_count] = physical;
            physical_count += 1;
        }
    }
    if (physical_count != physical_pages.len) proof.fail("SMP trap usable capacity");
}

fn trapStackPagePhysical(virtual: usize) u64 {
    var current = paging.getCurrentPageDirectory();
    for ([_]u6{ table.PML4_SHIFT, table.PDPT_SHIFT, table.PAGE_DIRECTORY_SHIFT }) |shift| {
        const entry = current[table.index(virtual, shift)];
        if (!table.isPresent(entry) or table.isLargePage(entry) or entry & table.USER != 0) proof.fail("SMP trap supervisor hierarchy");
        current = @ptrFromInt(paging.directMapAddress(table.address(entry)) orelse proof.fail("SMP trap table alias"));
    }
    const leaf = current[table.index(virtual, table.PAGE_TABLE_SHIFT)];
    if (!table.isPresent(leaf) or table.isLargePage(leaf)) proof.fail("SMP trap 4K backing");
    return table.address(leaf);
}

fn trapStackWord(top: usize, last: bool) *volatile u64 {
    return @ptrFromInt(if (last) top - @sizeOf(u64) else top - native_executor.TRAP_STACK_USABLE_BYTES);
}

fn trapStackCanary(index: u8, last: bool, selected: bool) u64 {
    return 0x9a57_0000_d15c_0000 | @as(u64, index) << 8 | (if (last) @as(u64, 2) else 1) | (if (selected) @as(u64, 4) else 0);
}

fn touchSelectedTrapStack(index: u8) void {
    if (cpu_identity.currentIndex() != index or x86.interruptsEnabled()) reject(index);
    const top = native_executor.prepareKernelStack();
    if (top != cpus[index].trap_stack_top) reject(index);
    // Payload accesses prove ownership; execution remains on the SIPI/BSP
    // kernel stack rather than entering through this prepared trap backing.
    for ([_]bool{ false, true }) |last| {
        const word = trapStackWord(top, last);
        if (word.* != trapStackCanary(index, last, false)) reject(index);
        word.* = trapStackCanary(index, last, true);
    }
}

fn proveTrapStacks() void {
    verifyTrapStackGeometry();
    for (&cpus, 0..) |*cpu, index| {
        if (cpu.observation.trap_stack_top != cpu.trap_stack_top) proof.fail("SMP selected trap stack top");
        for ([_]bool{ false, true }) |last| {
            if (trapStackWord(cpu.trap_stack_top, last).* != trapStackCanary(@intCast(index), last, true))
                proof.fail("SMP selected trap stack neighbor");
        }
    }
    proof.pass("SMP_16_TRAP_STACKS");
}

const ColdStackHardware = struct {
    gdtr: gdt.GdtPtr,
    selector: u16,
    descriptors: [7]u64,
    tss_base: usize,
    tss: gdt.Tss,
    cr0: usize,
    cr3: usize,
    cr4: usize,
    xcr0: u64,
    efer: u64,
    gs_base: u64,
    kernel_gs_base: u64,
    tsc_aux: u64,
    control_flags: usize,
};

fn captureColdStackHardware(index: u8, out: *ColdStackHardware) bool {
    if (cpu_identity.currentIndex() != index or x86.interruptsEnabled() or
        !paging.kernelAddressSpaceActive()) return false;
    const cr4 = x86.readCr4();
    if (cr4 & (x86.CR4_OSXSAVE | x86.CR4_FRED) != x86.CR4_OSXSAVE) return false;
    const xcr0 = x86.readXcr0();
    if (xcr0 != xstate.enabled_mask) return false;
    var gdtr: gdt.GdtPtr = undefined;
    asm volatile ("sgdt (%[table])"
        :
        : [table] "r" (&gdtr),
        : .{ .memory = true });
    const selector = asm volatile ("str %[selector]"
        : [selector] "=r" (-> u16),
    );
    if (selector != gdt.TSS_SEG or gdtr.limit != 55 or
        address.imagePhysicalAddress(gdtr.base) == null or
        address.imagePhysicalAddress(gdtr.base + gdtr.limit) == null) return false;
    const descriptors: *const volatile [7]u64 = @ptrFromInt(gdtr.base);
    const entries = descriptors.*;
    const low = entries[5];
    const high = entries[6];
    const tss_base = ((low >> 16) & 0xFF_FFFF) | ((low >> 32) & 0xFF00_0000) | (high << 32);
    if ((low >> 40) & 0xFF != 0x8B or high >> 32 != 0 or
        (low & 0xFFFF) | ((low >> 32) & 0xF0000) != @sizeOf(gdt.Tss) - 1 or
        address.imagePhysicalAddress(tss_base) == null or
        address.imagePhysicalAddress(tss_base + @sizeOf(gdt.Tss) - 1) == null) return false;
    const tss: *const volatile gdt.Tss = @ptrFromInt(tss_base);
    const flags = asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> usize),
    );
    const state = native_entry.current().*;
    if (state.native_entry_modes != 0 or tss.ist1 != gdt.doubleFaultStackTop() or
        tss.iomap_base != @sizeOf(gdt.Tss) or
        x86.readMsr(x86.IA32_GS_BASE_MSR) != @intFromPtr(native_entry.stateForCpu(index))) return false;
    out.* = .{
        .gdtr = gdtr,
        .selector = selector,
        .descriptors = entries,
        .tss_base = tss_base,
        .tss = tss.*,
        .cr0 = x86.readCr0(),
        .cr3 = x86.readCr3(),
        .cr4 = cr4,
        .xcr0 = xcr0,
        .efer = x86.readMsr(x86.EFER_MSR),
        .gs_base = x86.readMsr(x86.IA32_GS_BASE_MSR),
        .kernel_gs_base = x86.readMsr(x86.IA32_KERNEL_GS_BASE_MSR),
        .tsc_aux = x86.readMsr(x86.IA32_TSC_AUX_MSR),
        .control_flags = flags & ((1 << 9) | FLAG_DF | FLAG_AC),
    };
    return out.control_flags == 0;
}

fn proveColdStackOwner(index: u8) void {
    if (index != PREPARED_OWNER_CPU) return;
    if (cpu_identity.currentIndex() != index or x86.interruptsEnabled()) reject(index);
    const ordinary_top = cpus[index].stack_top;
    const guarded_top = cpus[index].trap_stack_top;
    const selected = native_entry.initializeCpu(index, ordinary_top);
    x86.writeMsr(x86.IA32_GS_BASE_MSR, @intFromPtr(selected));
    x86.writeMsr(x86.IA32_KERNEL_GS_BASE_MSR, 0);
    var hardware_before: ColdStackHardware = undefined;
    if (!captureColdStackHardware(index, &hardware_before) or hardware_before.tss.rsp0 != ordinary_top)
        reject(index);
    var neighbors: [PROOF_CPU_COUNT]native_entry.State = undefined;
    var canaries: [PROOF_CPU_COUNT][2]u64 = undefined;
    for (&neighbors, &canaries, 0..) |*state, *ends, cpu| {
        state.* = native_entry.stateForCpu(@intCast(cpu)).*;
        ends.* = .{ trapStackWord(cpus[cpu].trap_stack_top, false).*, trapStackWord(cpus[cpu].trap_stack_top, true).* };
    }
    // Exercise the production cold owner transaction. The independent oracle
    // decodes the actual loaded busy TSS, rather than reading its backing via
    // a production getter. This does not publish native entry readiness.
    if (!syscall64.setKernelStack(guarded_top)) reject(index);
    var hardware_guarded: ColdStackHardware = undefined;
    if (!captureColdStackHardware(index, &hardware_guarded)) reject(index);
    var expected_hardware = hardware_before;
    expected_hardware.tss.rsp0 = guarded_top;
    var expected_state = neighbors[index];
    expected_state.kernel_stack_top = guarded_top;
    const guarded_state = native_entry.current().*;
    if (!std.meta.eql(expected_hardware, hardware_guarded) or
        !std.mem.eql(u8, std.mem.asBytes(&expected_state), std.mem.asBytes(&guarded_state))) reject(index);
    for (&neighbors, 0..) |*state, cpu| {
        if (cpu == index) continue;
        const actual = native_entry.stateForCpu(@intCast(cpu)).*;
        if (!std.mem.eql(u8, std.mem.asBytes(state), std.mem.asBytes(&actual))) reject(index);
    }
    if (!syscall64.setKernelStack(ordinary_top)) reject(index);
    var hardware_restored: ColdStackHardware = undefined;
    if (!captureColdStackHardware(index, &hardware_restored) or
        !std.meta.eql(hardware_before, hardware_restored)) reject(index);
    for (&neighbors, &canaries, 0..) |*state, *ends, cpu| {
        const actual = native_entry.stateForCpu(@intCast(cpu)).*;
        if (!std.mem.eql(u8, std.mem.asBytes(state), std.mem.asBytes(&actual)) or
            trapStackWord(cpus[cpu].trap_stack_top, false).* != ends[0] or
            trapStackWord(cpus[cpu].trap_stack_top, true).* != ends[1]) reject(index);
        var cursor = cpus[cpu].trap_stack_top - native_executor.TRAP_STACK_USABLE_BYTES + @sizeOf(u64);
        while (cursor < cpus[cpu].trap_stack_top - @sizeOf(u64)) : (cursor += @sizeOf(u32)) {
            const word: *const volatile u32 = @ptrFromInt(cursor);
            if (word.* != TRAP_PAINT_WORD) reject(index);
        }
    }
    @atomicStore(u8, &cpus[index].cold_stack_checked, 1, .release);
}

fn bindProofContinuation(index: u8) void {
    if (cpu_identity.currentIndex() != index or x86.interruptsEnabled()) reject(index);
    const state = native_entry.initializeCpu(index, cpus[index].stack_top);
    // These are dormant canaries, not a native user continuation or a kernel
    // service port. This isolated gate never publishes ENTRY_READY or invokes
    // unsupported XSAVES/FRED setup. All five fields clear before IPI service.
    state.user_stack_pointer = 0x6000_0000 + @as(usize, index) * PAGE_BYTES;
    state.kernel_port = @intFromPtr(&cpus[index]);
    state.active_task_id = 0xfeed_0000_0000_1000 + @as(u64, index);
    state.userspace_xstate = @intFromPtr(&cpus[index].seed);
    state.kernel_xstate = @intFromPtr(&cpus[index].restored);
    state.resume_rsp = cpus[index].stack_top - x86.FRED_STACK_ALIGNMENT;
    state.resume_rip = @intFromPtr(&apEntry) + @as(usize, index);
    state.resume_requested = 0x4000_1000 + @as(u32, index);
    x86.writeMsr(x86.IA32_GS_BASE_MSR, @intFromPtr(state));
    x86.writeMsr(x86.IA32_KERNEL_GS_BASE_MSR, 0);
    if (!verifyCurrentGs(index, false)) reject(index);
}

fn proveContinuations() void {
    var cleared: [PROOF_CPU_COUNT]bool = @splat(false);
    const first_base = @intFromPtr(native_entry.stateForCpu(0));
    for (&cpus, 0..) |*cpu, index| {
        const slot = native_entry.stateForCpu(@intCast(index));
        if (cpu.observation.gs_base != @intFromPtr(slot) or
            @intFromPtr(slot) != first_base + index * @sizeOf(native_entry.State) or
            @intFromPtr(slot) % @alignOf(native_entry.State) != 0 or
            address.imagePhysicalAddress(@intFromPtr(slot)) == null or
            !continuationMatches(@intCast(index), false)) proof.fail("SMP GS slot ownership");
    }
    native_entry.clearContinuation();
    cleared[0] = true;
    if (!verifyCurrentGs(0, true)) proof.fail("SMP BSP continuation clear");
    verifyNeighbors(&cleared);
    // Clear opposite ends in turn: each AP owns its own RDPID-selected slot.
    // The BSP acquires completion before inspecting that slot and all neighbors.
    for (0..PROOF_CPU_COUNT - 1) |position| {
        const index: u8 = @intCast(if (position % 2 == 0) PROOF_CPU_COUNT - 1 - position / 2 else 1 + position / 2);
        @atomicStore(u8, &continuation_clear_target, index, .release);
        const deadline = tsc_clock.afterMilliseconds(2000);
        while (@atomicLoad(u8, &cpus[index].continuation_cleared, .acquire) != 1) {
            if (@atomicLoad(u8, &cpus[index].status, .acquire) != 1) proof.fail("SMP AP continuation clear");
            if (deadline.expired()) proof.fail("SMP continuation clear timeout");
            asm volatile ("pause");
        }
        cleared[index] = true;
        verifyNeighbors(&cleared);
    }
    proof.pass("SMP_16_CONTINUATION");
}

fn verifyNeighbors(cleared: *const [PROOF_CPU_COUNT]bool) void {
    for (cleared, 0..) |zero, index| {
        if (!continuationMatches(@intCast(index), zero)) proof.fail("SMP continuation neighbor changed");
    }
}

fn continuationMatches(index: u8, cleared: bool) bool {
    const state = native_entry.stateForCpu(index);
    return state.kernel_stack_top == cpus[index].stack_top and
        state.user_stack_pointer == 0x6000_0000 + @as(usize, index) * PAGE_BYTES and
        state.kernel_port == @intFromPtr(&cpus[index]) and
        state.active_task_id == 0xfeed_0000_0000_1000 + @as(u64, index) and
        state.native_entry_modes == 0 and
        state.userspace_xstate == (if (cleared) @as(usize, 0) else @intFromPtr(&cpus[index].seed)) and
        state.kernel_xstate == (if (cleared) @as(usize, 0) else @intFromPtr(&cpus[index].restored)) and
        state.resume_rsp == (if (cleared) @as(usize, 0) else cpus[index].stack_top - x86.FRED_STACK_ALIGNMENT) and
        state.resume_rip == (if (cleared) @as(usize, 0) else @intFromPtr(&apEntry) + @as(usize, index)) and
        state.resume_requested == (if (cleared) @as(u32, 0) else 0x4000_1000 + @as(u32, index));
}

fn gsWord(comptime field: []const u8) usize {
    return asm volatile (std.fmt.comptimePrint("movq %%gs:{d}, %[value]", .{@offsetOf(native_entry.State, field)})
        : [value] "=r" (-> usize),
        :
        : .{ .memory = true });
}

fn gsResumeRequested() u32 {
    return asm volatile (std.fmt.comptimePrint("movl %%gs:{d}, %[value]", .{@offsetOf(native_entry.State, "resume_requested")})
        : [value] "=r" (-> u32),
        :
        : .{ .memory = true });
}

fn gsEntryModes() u8 {
    return asm volatile (std.fmt.comptimePrint("movb %%gs:{d}, %[value]", .{@offsetOf(native_entry.State, "native_entry_modes")})
        : [value] "=r" (-> u8),
        :
        : .{ .memory = true });
}

fn verifyCurrentGs(index: u8, cleared: bool) bool {
    const state = native_entry.current();
    return cpu_identity.currentIndex() == index and continuationMatches(index, cleared) and
        x86.readMsr(x86.IA32_GS_BASE_MSR) == @intFromPtr(state) and x86.readMsr(x86.IA32_KERNEL_GS_BASE_MSR) == 0 and
        gsWord("kernel_stack_top") == state.kernel_stack_top and gsWord("user_stack_pointer") == state.user_stack_pointer and
        gsWord("kernel_port") == state.kernel_port and gsWord("active_task_id") == state.active_task_id and
        gsEntryModes() == 0 and gsWord("userspace_xstate") == state.userspace_xstate and
        gsWord("kernel_xstate") == state.kernel_xstate and gsWord("resume_rsp") == state.resume_rsp and
        gsWord("resume_rip") == state.resume_rip and gsResumeRequested() == state.resume_requested;
}

fn clearOwnContinuation(index: u8) void {
    while (@atomicLoad(u8, &continuation_clear_target, .acquire) != index) asm volatile ("pause");
    if (!verifyCurrentGs(index, false) or x86.interruptsEnabled()) reject(index);
    native_entry.clearContinuation();
    if (!verifyCurrentGs(index, true)) reject(index);
    @atomicStore(u8, &cpus[index].continuation_cleared, 1, .release);
}

fn proveCurrentRoots() void {
    const bsp_directory = paging.getCurrentPageDirectory();
    const bsp_cr3 = x86.readCr3();
    const runtime = table_backing.alloc(task_runtime.Runtime) orelse proof.fail("SMP dispatch runtime allocation");
    runtime.initializeAllocated();
    dispatch_runtime = runtime;
    var retirement = DispatchRetirement{};
    const task_sink = task_runtime.TaskRetirementSink{ .context = &retirement, .retire = DispatchRetirement.retire };
    const root_sink = task_runtime.AddressSpaceRetirementSink.init(DispatchRetirement, &retirement);
    const stop_sink = task_runtime.ExecutionStopSink{ .context = &retirement, .notify = DispatchRetirement.notifyStop };
    if (!runtime.bindTaskRetirementSink(task_sink) or !runtime.bindAddressSpaceRetirementSink(root_sink) or
        !runtime.bindExecutionStopSink(stop_sink))
        proof.fail("SMP dispatch retirement binding");
    for (0..private_roots.len) |index| {
        const cpu: u8 = @intCast(index + 1);
        const task = runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = cpu },
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 256, .endpoint_slots = 1, .shared_memory_bytes = 0 },
            .initial_component = .{ .label = "dispatch-owner", .entry = "dispatch-owner" },
            .local_only = true,
        }) catch proof.fail("SMP dispatch task creation");
        runtime.grantCapability(task.id, 700 + @as(u64, cpu)) catch proof.fail("SMP dispatch retained capability");
        dispatch_task_ids[index] = task.id;
        dispatch_address_ids[index] = task.address_space_id;
        dispatch_tickets[index] = runtime.reserveExecution(task, cpu) catch proof.fail("SMP dispatch CPU reservation");
        if (runtime.reserveExecution(task, 0)) |_| proof.fail("SMP dispatch duplicate task admitted") else |_| {}
    }
    // Runtime/cold metadata allocation is outside the exact root-frame delta.
    const baseline = paging.frameStats().allocated;
    for (&private_roots, 0..) |*space, index| {
        space.* = paging.createUserAddressSpace() catch proof.fail("SMP private root allocation");
        const physical = paging.directMapAddress(space.switch_cr3 & x86.CR3_ADDRESS_MASK) orelse proof.fail("SMP private root alias");
        if (physical != @intFromPtr(space.directory) or physical % PAGE_BYTES != 0 or
            space.directory == bsp_directory) proof.fail("SMP private root geometry");
        for (space.directory[0..256]) |entry| if (entry != 0) proof.fail("SMP private root lower aliases");
        for (private_roots[0..index]) |*earlier| {
            if (earlier.directory == space.directory or earlier.pcid == space.pcid) proof.fail("SMP private root alias");
        }
        const cpu: u8 = @intCast(index + 1);
        runtime.execution.bindOwnedRoot(dispatch_tickets[index], cpu, space.switch_cr3 & x86.CR3_ADDRESS_MASK) catch proof.fail("SMP dispatch root binding");
    }
    const admitted_frames = paging.frameStats().allocated;
    if (admitted_frames != baseline + private_roots.len) proof.fail("SMP private root accounting");
    // All APs remain CPL0 on empty user roots. Only the isolated standard-XSAVE
    // wait gate opens IF; native entry and userspace admission stay disabled.
    @atomicStore(u32, &root_phase, 1, .release);
    waitForRootPhase(1);
    if (paging.getCurrentPageDirectory() != bsp_directory or x86.readCr3() != bsp_cr3 or
        !paging.kernelAddressSpaceActive()) proof.fail("SMP BSP root isolation");
    // A delayed vector without a matching STOP has no execution authority.
    for (1..PROOF_CPU_COUNT) |cpu| {
        if (!smp.notifyExecutionStop(@intCast(cpu))) proof.fail("SMP unrequested stop prompt");
    }
    waitForStopPhase(1);
    for (cpus[1..]) |*cpu| {
        if (@atomicLoad(u8, &cpu.stop_observations, .acquire) != 0)
            proof.fail("SMP unrequested stop changed execution");
    }
    for (&private_roots, 0..) |*space, index| {
        const directory = space.directory;
        const pcid = space.pcid;
        const switch_cr3 = space.switch_cr3;
        if (paging.destroyUserAddressSpace(space)) |_| {
            proof.fail("SMP active remote root retired");
        } else |err| if (err != error.AddressSpaceActive) proof.fail("SMP active root rejection");
        if (space.directory != directory or space.pcid != pcid or space.switch_cr3 != switch_cr3 or
            paging.frameStats().allocated != admitted_frames) proof.fail("SMP active root mutation");
        for (space.directory[0..256]) |entry| if (entry != 0) proof.fail("SMP active root lower mutation");
        const task = runtime.find(dispatch_task_ids[index]) orelse proof.fail("SMP active dispatch task");
        const cpu: u8 = @intCast(index + 1);
        if (!runtime.terminateResolvedTask(task, 100 + @as(u64, cpu)) or runtime.terminateResolvedTask(task, 200 + @as(u64, cpu)) or
            task.state != .terminated or task.capability_count != 1 or task.execution_component_count != 1 or
            runtime.findAddressSpaceConst(dispatch_address_ids[index]) == null or
            dispatch_task_retirements != 0 or dispatch_root_retirements != 0)
            proof.fail("SMP dispatch resources retired before handoff");
        if (runtime.collectExecution(dispatch_tickets[index])) |_| proof.fail("SMP dispatch missing acknowledgement accepted") else |_| {}
    }
    waitForStopPhase(2);
    // An IPI return is separate from execution return. Repeat running STOP
    // prompts through the real Runtime sink while every root/resource is pinned.
    for (dispatch_tickets) |ticket| runtime.requestExecutionStop(ticket) catch proof.fail("SMP repeated stop request");
    waitForStopPhase(3);
    if (dispatch_stop_notifications != 2 * private_roots.len or dispatch_task_retirements != 0 or
        dispatch_root_retirements != 0 or paging.frameStats().allocated != admitted_frames)
        proof.fail("SMP stop prompt retired resources");
    for (dispatch_tickets, 0..) |ticket, index| {
        const cpu = &cpus[index + 1];
        const task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP stop retained task");
        if (@atomicLoad(u32, &cpu.stop_count, .acquire) != 3 or
            @atomicLoad(u8, &cpu.stop_observations, .acquire) != 6 or
            @atomicLoad(u8, &cpu.stop_environment_invalid, .acquire) != 0 or
            @atomicLoad(u32, &cpu.root_phase_completed, .acquire) != 1 or
            (runtime.execution.phase(ticket) catch proof.fail("SMP stop retained lease")) != .running or
            task.capability_count != 1 or task.execution_component_count != 1 or
            runtime.findAddressSpaceConst(dispatch_address_ids[index]) == null)
            proof.fail("SMP stop interrupt changed lifetime");
        if (runtime.collectExecution(ticket)) |_| proof.fail("SMP stop IRET accepted as execution acknowledgement") else |_| {}
    }
    proof.pass("SMP_16_STOP");
    // Request all stops together, but return and collect one actual AP at a
    // time in reverse CPU order. A neighbor's root must remain resident and
    // its task resources pinned until that neighbor acknowledges its own lease.
    @atomicStore(u32, &root_phase, 2, .release);
    for (0..private_roots.len) |position| {
        const cpu: u8 = @intCast(PROOF_CPU_COUNT - 1 - position);
        const index = cpu - 1;
        const deadline = tsc_clock.afterMilliseconds(2000);
        @atomicStore(u8, &dispatch_return_target, cpu, .release);
        while (@atomicLoad(u32, &cpus[cpu].root_phase_completed, .acquire) != 2) {
            if (@atomicLoad(u8, &cpus[cpu].status, .acquire) != 1 or deadline.expired()) proof.fail("SMP dispatch owner return timeout");
            asm volatile ("pause");
        }
        dispatch_collection_target = cpu;
        runtime.collectExecution(dispatch_tickets[index]) catch proof.fail("SMP dispatch exact acknowledgement collection");
        dispatch_collection_target = std.math.maxInt(u8);
        if (dispatch_task_retirements != position + 1 or dispatch_root_retirements != position + 1 or
            paging.frameStats().allocated != admitted_frames - position - 1 or
            runtime.execution.hasLeaseForTask(dispatch_task_ids[index])) proof.fail("SMP dispatch exact retirement accounting");
        if (runtime.collectExecution(dispatch_tickets[index])) |_| proof.fail("SMP dispatch duplicate collection") else |_| {}
        const retired_task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP dispatch retired record pin");
        if (retired_task.capability_count != 0 or retired_task.execution_component_count != 0 or
            runtime.findAddressSpaceConst(dispatch_address_ids[index]) != null) proof.fail("SMP dispatch completed resources retained");
        for (0..index) |neighbor| {
            const task = runtime.findConst(dispatch_task_ids[neighbor]) orelse proof.fail("SMP dispatch neighboring task");
            if (task.capability_count != 1 or task.execution_component_count != 1 or
                runtime.findAddressSpaceConst(dispatch_address_ids[neighbor]) == null or
                !runtime.execution.hasLeaseForTask(task.id) or
                @atomicLoad(u32, &cpus[neighbor + 1].root_phase_completed, .acquire) != 1)
                proof.fail("SMP dispatch neighboring ownership changed");
        }
    }
    waitForRootPhase(2);
    if (paging.frameStats().allocated != baseline or paging.getCurrentPageDirectory() != bsp_directory or
        x86.readCr3() != bsp_cr3) proof.fail("SMP restored root accounting");
    proof.pass("SMP_16_ROOTS");
    if (!runtime.unbindTaskRetirementSink(task_sink) or !runtime.unbindAddressSpaceRetirementSink(root_sink) or
        !runtime.unbindExecutionStopSink(stop_sink))
        proof.fail("SMP dispatch retirement unbinding");
    proof.pass("SMP_16_DISPATCH");
    proveSyscallBroker(runtime);
    provePreparedOwner(runtime);
    provePreparedTransport(runtime);
    provePromptedPreparedTransport(runtime);
    proveGuardedTrapStack(runtime);
    if (comptime @import("mapping_xstate_probe.zig").enabled)
        @import("mapping_xstate_probe.zig").run(runtime, cpus[PREPARED_OWNER_CPU].trap_stack_top, physical_cr3);
    runtime.reset();
    dispatch_runtime = null;
    table_backing.free(task_runtime.Runtime, runtime);
}

fn waitForRootPhase(phase: u32) void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    for (cpus[1..]) |*cpu| {
        while (@atomicLoad(u32, &cpu.root_phase_completed, .acquire) != phase) {
            if (@atomicLoad(u8, &cpu.status, .acquire) != 1) proof.fail("SMP current root state");
            if (deadline.expired()) proof.fail("SMP current root timeout");
            asm volatile ("pause");
        }
    }
}

// This second lease wave keeps the original Runtime/Coordinator alive, so
// epochs and mailbox sequences cannot be reset through an address-reuse fixture.
// Actual APs submit scalar envelopes from CPL0; the BSP stages cross-page wire
// requests and payloads through the production CPU-routed Executor adapter.
// The real Scheduler retires each arena after owner return; native user entry
// remains outside this isolated standard-XSAVE CPL0 guest.
fn proveSyscallBroker(runtime: *task_runtime.Runtime) void {
    const caps = table_backing.alloc(capability.CapabilityTable) orelse proof.fail("SMP broker capability allocation");
    caps.initializeAllocated();
    const endpoints = table_backing.alloc(endpoint.Table) orelse proof.fail("SMP broker endpoint allocation");
    endpoints.initializeAllocated();
    const shared = table_backing.alloc(shared_memory.Table) orelse proof.fail("SMP broker shared allocation");
    shared.* = shared_memory.Table.init();
    const kernel = table_backing.alloc(native_kernel.Kernel) orelse proof.fail("SMP broker kernel allocation");
    kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, runtime, caps, endpoints, shared);
    var port = component_port.KernelPort.init(kernel);
    port.syscall_caller_task_id = 999;
    port.syscall_header_prevalidated = true;
    var sources: [PROOF_CPU_COUNT]*native_executor.Executor = undefined;
    for (&sources) |*source| {
        source.* = table_backing.alloc(native_executor.Executor) orelse proof.fail("SMP broker Executor allocation");
        source.*.* = .{};
    }
    const scheduler = table_backing.alloc(native_scheduler.Scheduler) orelse proof.fail("SMP broker Scheduler allocation");
    scheduler.initializeAllocated(sources[0]);
    if (!native_scheduler.ArchitectureProof.bindDomain(scheduler, runtime)) proof.fail("SMP broker domain binding");
    for (sources[1..], 1..) |source, cpu| {
        if (!source.claimRuntimeBinding(scheduler, runtime) or !source.claimMappingRegistration(@intCast(cpu), scheduler, runtime))
            proof.fail("SMP broker source registration");
    }
    const receiver = runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 99 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = BROKER_PRIVATE_BYTES, .endpoint_slots = private_roots.len, .shared_memory_bytes = 0 },
        .local_only = true,
    }) catch proof.fail("SMP broker receiver creation");
    var receiving: [PROOF_CPU_COUNT - 1]u64 = undefined;
    for (0..private_roots.len) |index| {
        const cpu: u8 = @intCast(index + 1);
        const task = runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = 100 + @as(u64, cpu) },
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = BROKER_PRIVATE_BYTES, .endpoint_slots = 1, .shared_memory_bytes = 0 },
            .initial_component = .{ .label = "broker-owner", .entry = "broker-owner" },
            .local_only = true,
        }) catch proof.fail("SMP broker task creation");
        const authority = caps.mintBootRoot(.{
            .holder = task.owner,
            .issuer = kernel.policy_authority,
            .target = .{ .kind = .task, .id = task.id },
            .rights = .{ .task = .{ .task_terminate = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        }) catch proof.fail("SMP broker authority creation");
        runtime.grantCapability(task.id, authority.id) catch proof.fail("SMP broker capability attachment");
        const source = endpoints.create(object_ids.task(task.id), "broker-source", .{ .local_only = true }) catch proof.fail("SMP broker source endpoint");
        const destination = endpoints.create(object_ids.task(receiver.id), "broker-destination", .{ .local_only = true }) catch proof.fail("SMP broker destination endpoint");
        endpoints.connect(source.id, destination.id) catch proof.fail("SMP broker channel connection");
        const sending = caps.mintBootRoot(.{
            .holder = task.owner,
            .issuer = kernel.policy_authority,
            .target = .{ .kind = .endpoint, .id = source.id.raw() },
            .rights = .{ .endpoint = .{ .endpoint_send = true, .endpoint_recv = true, .endpoint_close = true } },
            .scope = .{ .task_id = task.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        }) catch proof.fail("SMP broker sending authority");
        runtime.grantCapability(task.id, sending.id) catch proof.fail("SMP broker sending attachment");
        const receive = caps.mintBootRoot(.{
            .holder = receiver.owner,
            .issuer = kernel.policy_authority,
            .target = .{ .kind = .endpoint, .id = destination.id.raw() },
            .rights = .{ .endpoint = .{ .endpoint_send = true, .endpoint_recv = true } },
            .scope = .{ .task_id = receiver.id, .local_only = true },
            .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
        }) catch proof.fail("SMP broker receiving authority");
        runtime.grantCapability(receiver.id, receive.id) catch proof.fail("SMP broker receiving attachment");
        receiving[index] = receive.id;
        dispatch_task_ids[index] = task.id;
        dispatch_address_ids[index] = task.address_space_id;
    }
    // CPU 0 owns the same numeric arena handle as every AP, with different
    // bytes at the same virtual addresses. Any BSP-arena fallback is observable.
    var anchor_space = paging.createUserAddressSpace() catch proof.fail("SMP broker anchor root allocation");
    paging.mapOwnedUserRange(&anchor_space, BROKER_PAGE, BROKER_PRIVATE_BYTES, .{ .writable = true }) catch proof.fail("SMP broker anchor pages");
    const sentinel: [abi.ENDPOINT_INLINE_BYTES]u8 = @splat(0xb5);
    paging.writeOwnedUserRange(&anchor_space, BROKER_PAYLOAD, &sentinel) catch proof.fail("SMP broker anchor sentinel");
    initializeBrokerOutputs(&anchor_space, 0, 0);
    prepareBrokerAddressRecord(runtime, receiver);
    if (!sources[0].installPreparedMappingForArchitectureProof(receiver, anchor_space, &broker_mapping_handles[0]))
        proof.fail("SMP broker anchor mapping admission");
    var root_frames: usize = 0;
    for (&private_roots, 0..) |*space, index| {
        const before_root = paging.frameStats().allocated;
        space.* = paging.createUserAddressSpace() catch proof.fail("SMP broker root allocation");
        paging.mapOwnedUserRange(space, BROKER_PAGE, BROKER_PRIVATE_BYTES, .{ .writable = true }) catch proof.fail("SMP broker private request pages");
        root_frames += paging.frameStats().allocated - before_root;
        const task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP broker copied request task");
        prepareBrokerAddressRecord(runtime, task);
        if (!sources[index + 1].installPreparedMappingForArchitectureProof(task, space.*, &broker_mapping_handles[index + 1]) or
            !broker_mapping_handles[index + 1].eql(broker_mapping_handles[0])) proof.fail("SMP broker colliding arena handles");
        const request = abi.EndpointSendWireRequest{
            .header = component_port.makeHeader(.endpoint_send, task.id),
            .endpoint_capability_id = task.capabilityIds()[1],
            .correlation_id = index + 1,
            .payload_address = BROKER_PAYLOAD,
            .payload_bytes = abi.ENDPOINT_INLINE_BYTES,
        };
        const payload = brokerPayload(@intCast(index + 1));
        paging.writeOwnedUserRange(space, BROKER_SEND_REQUEST, std.mem.asBytes(&request)) catch proof.fail("SMP broker cross-page wire copy");
        paging.writeOwnedUserRange(space, BROKER_PAYLOAD, &payload) catch proof.fail("SMP broker cross-page payload copy");
    }
    const admitted = paging.frameStats().allocated;
    const baseline = admitted - root_frames; // Cold arena backing is outside the exact root delta.
    if (root_frames != BROKER_ROOT_FRAMES * private_roots.len or caps.activeCount() != 3 * private_roots.len)
        proof.fail("SMP broker private hierarchy accounting");
    for (dispatch_task_ids, 0..) |task_id, index| {
        const task = runtime.findConst(task_id) orelse proof.fail("SMP broker lease task");
        dispatch_tickets[index] = runtime.reserveExecution(task, @intCast(index + 1)) catch proof.fail("SMP broker reservation");
        runtime.execution.bindOwnedRoot(dispatch_tickets[index], broker_mapping_handles[index + 1].value, private_roots[index].switch_cr3 & x86.CR3_ADDRESS_MASK) catch proof.fail("SMP broker private root binding");
    }
    dispatch_return_target = std.math.maxInt(u8);
    _ = event_wake.take();
    // Every AP is still IF0 behind phase zero and the BSP timer is masked.
    // Exercise the bounded no-doorbell path before publishing any request.
    brokerWait(0, null);
    if (@atomicLoad(u32, &broker_request_count, .acquire) != 0) proof.fail("SMP broker premature request interrupt");
    @atomicStore(u32, &broker_phase, 1, .release);
    // Doorbells may coalesce. One actual request interrupt must latch BSP work;
    // the published mailbox, rather than an interrupt count, owns each request.
    const request_deadline = tsc_clock.afterMilliseconds(2000);
    while (@atomicLoad(u32, &broker_request_count, .acquire) == 0) {
        if (request_deadline.expired()) proof.fail("SMP broker request interrupt timeout");
        brokerWait(0, null);
    }
    waitForBroker(.ipc_published);
    if (!event_wake.take().scheduler) proof.fail("SMP broker BSP wake latch");
    smp.shootdownKernel();
    waitForBrokerTlb();
    for (dispatch_tickets) |ticket| {
        if (runtime.execution.syscallIdle(ticket) or
            (runtime.execution.phase(ticket) catch proof.fail("SMP broker pending lease")) != .running)
            proof.fail("SMP broker pending request lost");
        if (runtime.collectExecution(ticket)) |_| proof.fail("SMP broker pending collection admitted") else |_| {}
    }
    for (dispatch_tickets, 0..) |ticket, index| {
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        runtime.execution.claimSyscallInto(ticket.cpu, &claim) catch proof.fail("SMP broker IPC claim");
        var copy: syscall_broker.CopySession = undefined;
        if (!sources[0].prepareSyscallCopySession(&claim, &copy)) proof.fail("SMP broker production copy session");
        syscall_broker.serviceClaim(&port, &claim, &copy, 50) catch proof.fail("SMP broker IPC service");
        const task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP broker IPC caller");
        if (task.state != .active or task.capability_count != 2 or runtime.execution.syscallIdle(ticket) or
            caps.activeCount() != 3 * private_roots.len or paging.frameStats().allocated != admitted)
            proof.fail("SMP broker IPC retained ownership");
        // Mutate both original inputs after invocation. The queued record must
        // retain the BSP snapshot without referring to either private span.
        const overwritten: [abi.ENDPOINT_INLINE_BYTES]u8 = @splat(0xee);
        const overwritten_wire: [@sizeOf(abi.EndpointSendWireRequest)]u8 = @splat(0xff);
        paging.writeOwnedUserRange(&private_roots[index], BROKER_PAYLOAD, &overwritten) catch proof.fail("SMP broker IPC source reuse");
        paging.writeOwnedUserRange(&private_roots[index], BROKER_SEND_REQUEST, &overwritten_wire) catch proof.fail("SMP broker IPC wire reuse");
        var payload: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
        const received = (kernel.endpointRecv(.{ .caller_task_id = receiver.id, .presented_capability_id = receiving[index], .target = .none }, receiver.id, &payload, 51) catch proof.fail("SMP broker IPC receive")) orelse proof.fail("SMP broker IPC missing publication");
        const expected = brokerPayload(ticket.cpu);
        if (received.message.sender_task_id != task.id or received.message.correlation_id != ticket.cpu or
            received.message.payload_len != payload.len or received.message.attached_capability_id != 0 or
            !std.mem.eql(u8, &expected, &payload) or endpoints.hasPendingForTask(object_ids.task(receiver.id)))
            proof.fail("SMP broker IPC snapshot mismatch");
        if (runtime.collectExecution(ticket)) |_| proof.fail("SMP broker IPC reply collected execution") else |_| {}
    }
    @atomicStore(u32, &broker_phase, 2, .release);
    for (dispatch_tickets) |ticket| if (!smp.notifySyscallCompletion(ticket.cpu)) proof.fail("SMP broker IPC completion transport");
    waitForBroker(.ipc_consumed);
    const copy_gift = proveBrokerReceives(runtime, kernel, &port, sources[0], receiver, &receiving, &anchor_space, admitted);
    proveBrokerCloses(runtime, kernel, &port, sources[0], receiver, &receiving, &anchor_space, &copy_gift, admitted);
    proof.pass("SMP_16_IPC");
    for (&private_roots, dispatch_task_ids) |*space, task_id| {
        const task = runtime.findConst(task_id) orelse proof.fail("SMP broker termination caller");
        const request = abi.TaskTerminateWireRequest{
            .header = component_port.makeHeader(.task_terminate, task.id),
            .task_capability_id = task.capabilityIds()[0],
        };
        paging.writeOwnedUserRange(space, BROKER_REQUEST, std.mem.asBytes(&request)) catch proof.fail("SMP broker cross-page termination copy");
    }
    const request_count = @atomicLoad(u32, &broker_request_count, .acquire);
    @atomicStore(u32, &broker_phase, BROKER_TERMINATE_REQUEST, .release);
    for (dispatch_tickets) |ticket| if (!smp.notifySyscallCompletion(ticket.cpu)) proof.fail("SMP broker next request wake");
    const terminate_deadline = tsc_clock.afterMilliseconds(2000);
    while (@atomicLoad(u32, &broker_request_count, .acquire) == request_count) {
        if (terminate_deadline.expired()) proof.fail("SMP broker termination interrupt timeout");
        brokerWait(0, null);
    }
    waitForBroker(.published);
    if (!event_wake.take().scheduler) proof.fail("SMP broker termination BSP wake");
    for (dispatch_tickets, 0..) |ticket, index| {
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        runtime.execution.claimSyscallInto(ticket.cpu, &claim) catch proof.fail("SMP broker BSP claim");
        var copy: syscall_broker.CopySession = undefined;
        if (!sources[0].prepareSyscallCopySession(&claim, &copy)) proof.fail("SMP broker production copy session");
        syscall_broker.serviceClaim(&port, &claim, &copy, 100 + @as(u64, ticket.cpu)) catch proof.fail("SMP broker copied invocation");
        const task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP broker retained caller");
        if (task.state != .terminated or task.capability_count != 3 or task.execution_component_count != 1 or
            runtime.findAddressSpaceConst(task.address_space_id) == null or
            runtime.execution.syscallIdle(ticket) or caps.activeCount() != 4 * private_roots.len + 1 or
            sources[index + 1].materializedCount() != 1 or sources[0].materializedCount() != 1 or paging.frameStats().allocated != admitted)
            proof.fail("SMP broker completion prematurely retired resources");
        if (runtime.collectExecution(ticket)) |_| proof.fail("SMP broker unconsumed collection admitted") else |_| {}
        if (syscall_broker.serviceClaim(&port, &claim, &copy, 500)) |_| proof.fail("SMP broker repeated invocation admitted") else |_| {}
    }
    if (port.syscall_caller_task_id != 999 or !port.syscall_header_prevalidated or !verifyCurrentGs(0, true))
        proof.fail("SMP broker BSP caller contamination");
    @atomicStore(u32, &broker_phase, BROKER_TERMINATE_REPLY, .release);
    for (dispatch_tickets) |ticket| if (!smp.notifySyscallCompletion(ticket.cpu)) proof.fail("SMP broker completion transport");
    waitForBroker(.consumed);
    for (0..private_roots.len) |position| {
        const cpu: u8 = @intCast(PROOF_CPU_COUNT - 1 - position);
        const index = cpu - 1;
        const task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP broker post-reply task");
        if (task.capability_count != 3 or caps.activeCount() != 4 * private_roots.len + 1 - 3 * position or
            !runtime.execution.syscallIdle(dispatch_tickets[index]) or
            (runtime.execution.phase(dispatch_tickets[index]) catch proof.fail("SMP broker post-reply lease")) != .running)
            proof.fail("SMP broker reply acknowledged execution");
        if (runtime.collectExecution(dispatch_tickets[index])) |_| proof.fail("SMP broker consumed collection without return") else |_| {}
        @atomicStore(u8, &dispatch_return_target, cpu, .release);
        if (!smp.notifySyscallCompletion(cpu)) proof.fail("SMP broker return wake");
        const deadline = tsc_clock.afterMilliseconds(2000);
        while (@atomicLoad(u8, &cpus[cpu].broker_returned, .acquire) != 1) {
            if (deadline.expired() or @atomicLoad(u8, &cpus[cpu].status, .acquire) != 1) proof.fail("SMP broker return timeout");
            asm volatile ("pause");
        }
        dispatch_collection_target = cpu;
        runtime.collectExecution(dispatch_tickets[index]) catch proof.fail("SMP broker exact return collection");
        dispatch_collection_target = std.math.maxInt(u8);
        if (sources[cpu].materializedCount() != 0 or sources[cpu].mappingHandle(dispatch_address_ids[index]) != null or
            sources[0].materializedCount() != 1 or runtime.findAddressSpaceConst(dispatch_address_ids[index]) != null or
            task.capability_count != 0 or task.execution_component_count != 0 or
            paging.frameStats().allocated != admitted - BROKER_ROOT_FRAMES * (position + 1) or
            runtime.execution.hasLeaseForTask(task.id)) proof.fail("SMP broker retirement accounting");
        if (runtime.collectExecution(dispatch_tickets[index])) |_| proof.fail("SMP broker duplicate collection") else |_| {}
    }
    if (paging.frameStats().allocated != baseline or caps.activeCount() != private_roots.len + 1 or !paging.kernelAddressSpaceActive())
        proof.fail("SMP broker cleanup ownership");
    if (!(runtime.terminateTask(receiver.id, 600) catch proof.fail("SMP broker receiver retirement")) or
        caps.activeCount() != 0 or endpoints.activeCount() != 0 or sources[0].materializedCount() != 0 or
        paging.frameStats().allocated != baseline - BROKER_ROOT_FRAMES) proof.fail("SMP broker channel cleanup");
    scheduler.deinit();
    for (sources) |source| {
        if (source.registration_cpu != null or source.binding_owner != null or source.bound_runtime != null or source.materializedCount() != 0)
            proof.fail("SMP broker drained domain");
        table_backing.free(native_executor.Executor, source);
    }
    table_backing.free(native_scheduler.Scheduler, scheduler);
    kernel.deinit();
    endpoints.deinit();
    shared.deinit();
    table_backing.free(native_kernel.Kernel, kernel);
    table_backing.free(endpoint.Table, endpoints);
    table_backing.free(shared_memory.Table, shared);
    table_backing.free(capability.CapabilityTable, caps);
    @atomicStore(u32, &broker_phase, BROKER_DONE, .release);
    proof.pass("SMP_16_BROKER");
}

// Execute the actual prepared owner body on CPU 1 with physical register/root
// operations. Only the user-entry instruction is replaced by a CPL0 callback;
// this does not execute the prepared trap stack or native XSAVES/FRED entry.
fn provePreparedOwner(runtime: *task_runtime.Runtime) void {
    if (cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or
        !paging.kernelAddressSpaceActive() or runtime.execution.hasLeases() or preparedBorrowCount(runtime) != 0)
        proof.fail("SMP prepared fixture owner");
    const bsp_cr3 = x86.readCr3();
    const anchor = table_backing.alloc(native_executor.Executor) orelse proof.fail("SMP prepared anchor allocation");
    anchor.* = .{};
    const source = table_backing.alloc(native_executor.Executor) orelse proof.fail("SMP prepared owner allocation");
    source.* = .{};
    const scheduler = table_backing.alloc(native_scheduler.Scheduler) orelse proof.fail("SMP prepared Scheduler allocation");
    scheduler.initializeAllocated(anchor);
    if (!native_scheduler.ArchitectureProof.bindDomain(scheduler, runtime) or
        !source.claimRuntimeBinding(scheduler, runtime) or
        !source.claimMappingRegistration(PREPARED_OWNER_CPU, scheduler, runtime))
        proof.fail("SMP prepared domain binding");
    const task = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 201 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = PAGE_BYTES, .endpoint_slots = 0, .shared_memory_bytes = 0 },
        .initial_component = .{ .label = "prepared-owner", .entry = "prepared-owner" },
        .local_only = true,
    }) catch proof.fail("SMP prepared task creation");
    const task_id = task.id;
    const address_space_id = task.address_space_id;
    const context = native_executor.UserContext64{
        .rax = 0x8111_2222_3333_4444,
        .rbx = 0x8222_3333_4444_5555,
        .rcx = 0x8333_4444_5555_6666,
        .rdx = 0x8444_5555_6666_7777,
        .rbp = 0x8555_6666_7777_8888,
        .rsi = 0x8666_7777_8888_9999,
        .rdi = 0x8777_8888_9999_aaaa,
        .r8 = 0x8888_9999_aaaa_bbbb,
        .r9 = 0x8999_aaaa_bbbb_cccc,
        .r10 = 0x8aaa_bbbb_cccc_dddd,
        .r11 = 0x8bbb_cccc_dddd_eeee,
        .r12 = 0x8ccc_dddd_eeee_ffff,
        .r13 = 0x8ddd_eeee_ffff_1111,
        .r14 = 0x8eee_ffff_1111_2222,
        .r15 = 0x8fff_1111_2222_3333,
        .instruction_pointer = 0x4000_1000,
        .stack_pointer = 0x7fff_f000,
        .flags = 0x202,
    };
    const before_root = paging.frameStats().allocated;
    const space = paging.createUserAddressSpace() catch proof.fail("SMP prepared root allocation");
    if (paging.frameStats().allocated != before_root + 1) proof.fail("SMP prepared empty root accounting");
    var handle: native_executor.MappingHandle = undefined;
    if (!source.installPreparedExecutionMappingForArchitectureProof(task, space, context, &handle))
        proof.fail("SMP prepared mapping installation");
    // Arena and private xstate allocation precede this exact root-retirement
    // delta; their allocator lifetime is checked by domain teardown separately.
    const admitted = paging.frameStats().allocated;
    prepared_owner_source = source;
    for (&prepared_neighbors, 0..) |*snapshot, cpu| {
        snapshot.* = native_entry.stateForCpu(@intCast(cpu)).*;
        if (snapshot.native_entry_modes != 0) proof.fail("SMP prepared native entry admission");
    }
    prepared_owner_expectation = .{
        .task_id = task_id,
        .physical_root = space.switch_cr3 & x86.CR3_ADDRESS_MASK,
        .user_context = context,
        .receipt = .{ .outcome = .yielded, .ui_revision = 0x1357_2468_abcd_ef01 },
    };
    const first = runtime.reserveExecution(task, PREPARED_OWNER_CPU) catch proof.fail("SMP prepared first reservation");
    if (first.epoch <= dispatch_tickets[PREPARED_OWNER_CPU - 1].epoch or
        !source.bindPreparedExecutionForArchitectureProof(task, handle, first, &prepared_command))
        proof.fail("SMP prepared first publication");
    prepared_stale_command = prepared_command;
    @atomicStore(u32, &prepared_phase, 1, .release);
    waitForPreparedOwner(1);
    verifyPreparedOwnerReturn(runtime, source, first, admitted);
    var returned: dispatch_ownership.ReturnRecord = undefined;
    runtime.execution.consumePreparedReturnInto(first, &returned) catch proof.fail("SMP prepared first receipt");
    if (!std.meta.eql(returned, prepared_owner_expectation.receipt)) proof.fail("SMP prepared yielded receipt scalars");
    rejectRepeatedPreparedConsume(runtime, first);
    runtime.collectExecution(first) catch proof.fail("SMP prepared first collection");
    if (preparedBorrowCount(runtime) != 0 or runtime.execution.hasLeases() or source.materializedCount() != 1 or
        !source.mappingHandle(address_space_id).?.eql(handle) or task.state != .active or
        task.execution_component_count != 1 or runtime.findAddressSpaceConst(address_space_id) == null or
        paging.frameStats().allocated != admitted)
        proof.fail("SMP prepared first retained mapping");

    // The genuine yield handler captured these exact register substitutions.
    // Reuse that cached continuation in the next prepared epoch.
    prepared_owner_expectation.user_context.rax = 1;
    prepared_owner_expectation.user_context.rdx = returned.ui_revision;
    prepared_owner_expectation.user_context.rsi = @backingInt(@import("../../native/task/userspace_bootstrap_mailbox.zig").YieldDisposition.runnable);
    prepared_owner_expectation.user_context.instruction_pointer += 4;
    prepared_owner_expectation.receipt = .{
        .outcome = .faulted,
        .fault_vector = 14,
        .fault_error_code = 0x8000_0017,
        .fault_instruction_pointer = 0x4000_1234,
        .fault_address = 0x4000_5678,
    };
    const second = runtime.reserveExecution(task, PREPARED_OWNER_CPU) catch proof.fail("SMP prepared second reservation");
    if (second.issuer != first.issuer or second.epoch <= first.epoch or
        !source.bindPreparedExecutionForArchitectureProof(task, handle, second, &prepared_command))
        proof.fail("SMP prepared second publication");
    @atomicStore(u32, &prepared_phase, 2, .release);
    waitForPreparedOwner(2);
    verifyPreparedOwnerReturn(runtime, source, second, admitted);
    if (@atomicLoad(u32, &prepared_callback_count, .acquire) != 2 or prepared_xstate_address == 0 or
        !(runtime.terminateTask(task_id, 900) catch proof.fail("SMP prepared deferred termination")) or
        task.state != .terminated or task.execution_component_count != 1 or
        runtime.findAddressSpaceConst(address_space_id) == null or source.materializedCount() != 1 or
        paging.frameStats().allocated != admitted)
        proof.fail("SMP prepared fault retired before receipt");
    if (runtime.collectExecution(second)) |_| proof.fail("SMP prepared unconsumed termination collected") else |_| {}
    runtime.execution.consumePreparedReturnInto(second, &returned) catch proof.fail("SMP prepared fault receipt");
    if (!std.meta.eql(returned, prepared_owner_expectation.receipt)) proof.fail("SMP prepared fault receipt scalars");
    rejectRepeatedPreparedConsume(runtime, second);
    runtime.collectExecution(second) catch proof.fail("SMP prepared fault collection");
    if (!native_executor.collectRegisteredRetiredMappings(scheduler, runtime) or
        source.materializedCount() != 0 or source.mappingHandle(address_space_id) != null or
        runtime.findAddressSpaceConst(address_space_id) != null or task.execution_component_count != 0 or
        preparedBorrowCount(runtime) != 0 or runtime.execution.hasLeases() or paging.frameStats().allocated != admitted - 1)
        proof.fail("SMP prepared root retirement accounting");

    const replacement = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 202 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 1, .memory_bytes = 0, .endpoint_slots = 0, .shared_memory_bytes = 0 },
        .local_only = true,
    }) catch proof.fail("SMP prepared replacement task");
    const replacement_ticket = runtime.reserveExecution(replacement, PREPARED_OWNER_CPU) catch proof.fail("SMP prepared replacement reservation");
    if (replacement_ticket.issuer != first.issuer or replacement_ticket.epoch <= second.epoch or
        replacement.id == task_id) proof.fail("SMP prepared replacement identity");
    @atomicStore(u32, &prepared_phase, 3, .release);
    waitForPreparedOwner(3);
    if (prepared_owner_ran or @atomicLoad(u32, &prepared_callback_count, .acquire) != 2 or
        (runtime.execution.phase(replacement_ticket) catch proof.fail("SMP prepared replacement lease")) != .reserved or
        !runtime.execution.hasLeaseForTask(replacement.id) or preparedBorrowCount(runtime) != 1 or
        source.materializedCount() != 0 or paging.frameStats().allocated != admitted - 1)
        proof.fail("SMP prepared stale retry changed replacement");
    verifyPreparedNeighbors();
    runtime.cancelUnstartedExecution(replacement_ticket) catch proof.fail("SMP prepared replacement cancellation");
    runtime.collectExecution(replacement_ticket) catch proof.fail("SMP prepared replacement collection");
    if (!(runtime.terminateTask(replacement.id, 901) catch proof.fail("SMP prepared replacement retirement")))
        proof.fail("SMP prepared replacement termination");
    scheduler.deinit();
    for ([_]*native_executor.Executor{ anchor, source }) |executor| {
        if (executor.registration_cpu != null or executor.binding_owner != null or executor.bound_runtime != null or
            executor.materializedCount() != 0) proof.fail("SMP prepared drained domain");
        table_backing.free(native_executor.Executor, executor);
    }
    table_backing.free(native_scheduler.Scheduler, scheduler);
    prepared_owner_source = null;
    if (preparedBorrowCount(runtime) != 0 or runtime.execution.hasLeases() or paging.frameStats().allocated != admitted - 1 or
        !paging.kernelAddressSpaceActive() or x86.readCr3() != bsp_cr3 or x86.interruptsEnabled())
        proof.fail("SMP prepared final ownership");
    @atomicStore(u32, &prepared_phase, PREPARED_OWNER_DONE, .release);
    proof.pass("SMP_AP_PREPARED");
}

fn waitForPreparedOwner(phase: u32) void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    while (@atomicLoad(u32, &prepared_completed, .acquire) != phase) {
        if (deadline.expired() or @atomicLoad(u8, &cpus[PREPARED_OWNER_CPU].status, .acquire) != 1)
            proof.fail("SMP prepared owner completion timeout");
        asm volatile ("pause");
    }
}

fn preparedBorrowCount(runtime: *const task_runtime.Runtime) u32 {
    var count: u32 = 0;
    for (runtime.task_borrow_counts) |pinned| count += pinned;
    return count;
}

fn verifyPreparedOwnerReturn(runtime: *task_runtime.Runtime, source: *native_executor.Executor, ticket: dispatch_ownership.Ticket, admitted: usize) void {
    if (!prepared_owner_ran) proof.fail("SMP prepared owner did not run");
    if (preparedBorrowCount(runtime) != 1) proof.fail("SMP prepared returned borrow count");
    if (!runtime.execution.hasLeaseForTask(prepared_owner_expectation.task_id)) proof.fail("SMP prepared returned task lease");
    if ((runtime.execution.phase(ticket) catch proof.fail("SMP prepared returned lease")) != .returned)
        proof.fail("SMP prepared returned phase");
    // syscallIdle is intentionally a running-owner query. The actual prepared
    // ACK and subsequent receipt consumption enforce mailbox idleness while
    // this BSP observes the returned phase.
    if (source.active_task_id != 0) proof.fail("SMP prepared returned active task");
    if (source.active_mapping != null) proof.fail("SMP prepared returned active mapping");
    if (source.active_dispatch_lease != null) proof.fail("SMP prepared returned active ticket");
    if (!std.meta.eql(source.dispatch_quantum, native_executor.DispatchQuantum{})) proof.fail("SMP prepared returned quantum");
    if (source.materializedCount() != 1) proof.fail("SMP prepared returned cached mapping");
    if (paging.frameStats().allocated != admitted) proof.fail("SMP prepared returned frame delta");
    if (!paging.kernelAddressSpaceActive()) proof.fail("SMP prepared returned BSP root");
    if (x86.interruptsEnabled()) proof.fail("SMP prepared returned BSP IF");
    if (runtime.collectExecution(ticket)) |_| proof.fail("SMP prepared unconsumed receipt collected") else |_| {}
    verifyPreparedNeighbors();
}

fn rejectRepeatedPreparedConsume(runtime: *task_runtime.Runtime, ticket: dispatch_ownership.Ticket) void {
    const canary = dispatch_ownership.ReturnRecord{ .outcome = .faulted, .ui_revision = 0xffff_aaaa_5555_1234, .fault_vector = 13 };
    var unchanged = canary;
    if (runtime.execution.consumePreparedReturnInto(ticket, &unchanged)) |_| {
        proof.fail("SMP prepared duplicate receipt consumed");
    } else |err| if (err != error.WrongPhase) proof.fail("SMP prepared duplicate receipt error");
    if (!std.meta.eql(unchanged, canary)) proof.fail("SMP prepared rejected receipt mutated output");
}

fn verifyPreparedNeighbors() void {
    for (&prepared_neighbors, 0..) |*expected, cpu| {
        const actual = native_entry.stateForCpu(@intCast(cpu)).*;
        if (!std.mem.eql(u8, std.mem.asBytes(&actual), std.mem.asBytes(expected)) or actual.native_entry_modes != 0)
            proof.fail("SMP prepared continuation neighbor mutation");
        for ([_]bool{ false, true }) |last| {
            if (trapStackWord(cpus[cpu].trap_stack_top, last).* != trapStackCanary(@intCast(cpu), last, true))
                proof.fail("SMP prepared trap backing neighbor mutation");
        }
    }
}

fn preparedOwnerCallback(context: *anyopaque, entry: *const native_executor.ArchitecturePreparedEntry) dispatch_ownership.ReturnRecord {
    if (context != @as(*anyopaque, @ptrCast(&prepared_owner_expectation)) or cpu_identity.currentIndex() != PREPARED_OWNER_CPU or
        x86.interruptsEnabled() or paging.kernelAddressSpaceActive() or
        x86.readCr3() & x86.CR3_ADDRESS_MASK != prepared_owner_expectation.physical_root or
        entry.task_id != prepared_owner_expectation.task_id or entry.physical_root != prepared_owner_expectation.physical_root or
        entry.trap_stack_top != cpus[PREPARED_OWNER_CPU].trap_stack_top or
        native_executor.prepareKernelStack() != entry.trap_stack_top or
        gsWord("kernel_stack_top") != entry.trap_stack_top or gsWord("active_task_id") != entry.task_id or gsEntryModes() != 0 or
        !std.meta.eql(entry.user_context.*, prepared_owner_expectation.user_context) or
        !std.meta.eql(entry.dispatch_quantum, native_executor.DispatchQuantum.begin(entry.task_id, cpus[PREPARED_OWNER_CPU].observation.timer.cached_ticks)) or
        entry.xstate_address == 0 or entry.xstate_address % xstate.alignment != 0)
        proof.fail("SMP prepared actual entry evidence");
    const rsp = asm volatile ("mov %%rsp, %[value]"
        : [value] "=r" (-> usize),
    );
    if (rsp <= cpus[PREPARED_OWNER_CPU].stack_guard + PAGE_BYTES or rsp >= cpus[PREPARED_OWNER_CPU].stack_top)
        proof.fail("SMP prepared privileged callback stack");
    const state: *align(xstate.alignment) const xstate.State = @ptrFromInt(entry.xstate_address);
    if (state.pkru != 0 or state.reserved != 0 or std.mem.readInt(u32, state.image[24..28], .little) != 0x1f80 or
        std.mem.readInt(u64, state.image[512..520], .little) != 0 or
        std.mem.readInt(u64, state.image[520..528], .little) != (@as(u64, 1) << 63 | xstate.enabled_mask))
        proof.fail("SMP prepared private xstate image");
    if (prepared_xstate_address == 0) prepared_xstate_address = entry.xstate_address else if (prepared_xstate_address != entry.xstate_address)
        proof.fail("SMP prepared private xstate changed between epochs");
    for (&prepared_neighbors, 0..) |*expected, cpu| {
        if (cpu == PREPARED_OWNER_CPU) continue;
        const actual = native_entry.stateForCpu(@intCast(cpu)).*;
        if (!std.mem.eql(u8, std.mem.asBytes(&actual), std.mem.asBytes(expected))) proof.fail("SMP prepared entry changed neighbor");
    }
    _ = @atomicRmw(u32, &prepared_callback_count, .Add, 1, .monotonic);
    return prepared_owner_expectation.receipt;
}

fn holdPreparedOwner(index: u8) void {
    if (index != PREPARED_OWNER_CPU) return;
    const saved_entry = native_entry.current().*;
    const assigned_top = native_executor.preparedKernelStackForCpu(index) orelse reject(index);
    if (assigned_top != cpus[index].trap_stack_top or saved_entry.native_entry_modes != 0 or x86.interruptsEnabled()) reject(index);
    for (1..PREPARED_OWNER_DONE) |phase| {
        while (@atomicLoad(u32, &prepared_phase, .acquire) != phase) asm volatile ("pause");
        // Bind only durable selected GS metadata. The callback keeps executing
        // on the ordinary AP stack, and TSS/native entry admission is unchanged.
        _ = native_entry.initializeCpu(index, assigned_top);
        const source = prepared_owner_source orelse reject(index);
        prepared_owner_ran = source.runPreparedExecutionForArchitectureProof(
            if (phase == 3) &prepared_stale_command else &prepared_command,
            preparedOwnerCallback,
            &prepared_owner_expectation,
        );
        // ACK ended all domain/payload accesses inside the real owner body.
        // Restore only retained GS backing, then publish independent completion.
        native_entry.current().* = saved_entry;
        if (!paging.kernelAddressSpaceActive() or x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3 or
            x86.interruptsEnabled() or gsEntryModes() != 0) reject(index);
        @atomicStore(u32, &prepared_completed, @intCast(phase), .release);
    }
    while (@atomicLoad(u32, &prepared_phase, .acquire) != PREPARED_OWNER_DONE) asm volatile ("pause");
}

// The queued proof retains the same native admission limits as the direct
// proof above. Its additional witness is durable command/source ownership:
// execution ACK alone cannot release a claimed static transport channel.
fn provePreparedTransport(runtime: *task_runtime.Runtime) void {
    if (cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or
        runtime.execution.hasLeases() or preparedBorrowCount(runtime) != 0 or
        dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution)) proof.fail("SMP transport fixture owner");
    const bsp_cr3 = x86.readCr3();
    const anchor = table_backing.alloc(native_executor.Executor) orelse proof.fail("SMP transport anchor allocation");
    anchor.* = .{};
    const source = table_backing.alloc(native_executor.Executor) orelse proof.fail("SMP transport source allocation");
    source.* = .{};
    const scheduler = table_backing.alloc(native_scheduler.Scheduler) orelse proof.fail("SMP transport Scheduler allocation");
    scheduler.initializeAllocated(anchor);
    if (!native_scheduler.ArchitectureProof.bindDomain(scheduler, runtime) or
        !source.claimRuntimeBinding(scheduler, runtime) or
        !source.claimMappingRegistration(PREPARED_OWNER_CPU, scheduler, runtime)) proof.fail("SMP transport domain binding");
    const task = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 203 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = PAGE_BYTES, .endpoint_slots = 0, .shared_memory_bytes = 0 },
        .initial_component = .{ .label = "prepared-transport", .entry = "prepared-transport" },
        .local_only = true,
    }) catch proof.fail("SMP transport task creation");
    const task_id = task.id;
    const address_space_id = task.address_space_id;
    var context = prepared_owner_expectation.user_context;
    context.rax = 0xa123_4567_89ab_cdef;
    context.instruction_pointer = 0x4000_2000;
    const before_root = paging.frameStats().allocated;
    const space = paging.createUserAddressSpace() catch proof.fail("SMP transport root allocation");
    if (paging.frameStats().allocated != before_root + 1) proof.fail("SMP transport root accounting");
    var handle: native_executor.MappingHandle = undefined;
    if (!source.installPreparedExecutionMappingForArchitectureProof(task, space, context, &handle))
        proof.fail("SMP transport mapping installation");
    const admitted = paging.frameStats().allocated;
    for (&prepared_neighbors, 0..) |*snapshot, cpu| {
        snapshot.* = native_entry.stateForCpu(@intCast(cpu)).*;
        if (snapshot.native_entry_modes != 0) proof.fail("SMP transport native entry admission");
    }
    prepared_xstate_address = 0;
    @atomicStore(u32, &prepared_callback_count, 0, .monotonic);
    prepared_owner_expectation = .{
        .task_id = task_id,
        .physical_root = space.switch_cr3 & x86.CR3_ADDRESS_MASK,
        .user_context = context,
        .receipt = .{ .outcome = .yielded, .ui_revision = 0x2468_1357_fedc_ba98 },
    };
    var command: native_executor.ArchitecturePreparedCommand = undefined;
    const first = publishTransportEpoch(runtime, source, task, handle, &command);
    transport_stale_key = transport_key;
    transport_claim_canary = .{ .key = transport_key, .command = command };
    @atomicStore(u32, &transport_phase, 1, .release);
    waitForTransportWord(&transport_returned, 1);
    verifyTransportReturned(runtime, source, first, admitted);
    var returned: dispatch_ownership.ReturnRecord = undefined;
    runtime.execution.consumePreparedReturnInto(first, &returned) catch proof.fail("SMP transport yield receipt");
    if (!std.meta.eql(returned, prepared_owner_expectation.receipt)) proof.fail("SMP transport yield scalars");
    rejectRepeatedPreparedConsume(runtime, first);
    rejectTransportCollection(runtime, scheduler, source, first, address_space_id, admitted);
    @atomicStore(u32, &transport_released, 1, .release);
    verifyTransportCompletion(1, .owner_returned);
    runtime.collectExecution(first) catch proof.fail("SMP transport yield collection");
    verifyTransportRetained(runtime, source, task, handle, admitted);

    // Withdrawal arbitrates the real pending channel without launching the AP.
    // A later sequence must reject this key even while its replacement is live.
    const withdrawn = publishTransportEpoch(runtime, source, task, handle, &command);
    const withdrawn_key = transport_key;
    dispatch_transport.global.withdraw(withdrawn_key) catch proof.fail("SMP transport pending withdrawal");
    if (dispatch_transport.global.withdraw(withdrawn_key)) |_| proof.fail("SMP transport duplicate withdrawal") else |err| {
        if (err != error.WrongPhase) proof.fail("SMP transport withdrawal error");
    }
    runtime.cancelUnstartedExecution(withdrawn) catch proof.fail("SMP transport withdrawn cancellation");
    consumeTransportUnavailable(runtime, withdrawn);
    var completion: dispatch_transport.Completion = .owner_returned;
    dispatch_transport.global.completionInto(withdrawn_key, &completion) catch proof.fail("SMP transport withdrawn completion");
    if (completion != .unstarted) proof.fail("SMP transport withdrawal executed");
    runtime.collectExecution(withdrawn) catch proof.fail("SMP transport withdrawn collection");
    verifyTransportRetained(runtime, source, task, handle, admitted);

    const stopped = publishTransportEpoch(runtime, source, task, handle, &command);
    completion = .owner_returned;
    if (dispatch_transport.global.completionInto(withdrawn_key, &completion)) |_| proof.fail("SMP transport stale replacement key") else |err| {
        if (err != error.StaleKey or completion != .owner_returned) proof.fail("SMP transport stale completion output");
    }
    runtime.requestExecutionStop(stopped) catch proof.fail("SMP transport pending STOP");
    @atomicStore(u32, &transport_phase, 2, .release);
    verifyTransportCompletion(2, .unstarted);
    if (transport_owner_ran or @atomicLoad(u32, &prepared_callback_count, .acquire) != 1 or
        (runtime.execution.phase(stopped) catch proof.fail("SMP transport stopped phase")) != .ready)
        proof.fail("SMP transport stopped owner started");
    runtime.cancelUnstartedExecution(stopped) catch proof.fail("SMP transport stopped cancellation");
    consumeTransportUnavailable(runtime, stopped);
    runtime.collectExecution(stopped) catch proof.fail("SMP transport stopped collection");
    verifyTransportRetained(runtime, source, task, handle, admitted);

    const canceled = publishTransportEpoch(runtime, source, task, handle, &command);
    @atomicStore(u32, &transport_phase, 3, .release);
    waitForTransportWord(&transport_claimed, 3);
    if (dispatch_transport.global.withdraw(transport_key)) |_| proof.fail("SMP transport withdrew claimed command") else |err| {
        if (err != error.WrongPhase) proof.fail("SMP transport claimed withdrawal error");
    }
    runtime.cancelUnstartedExecution(canceled) catch proof.fail("SMP transport claimed cancellation");
    consumeTransportUnavailable(runtime, canceled);
    rejectTransportCollection(runtime, scheduler, source, canceled, address_space_id, admitted);
    @atomicStore(u32, &transport_released, 3, .release);
    verifyTransportCompletion(3, .unstarted);
    if (transport_owner_ran or @atomicLoad(u32, &prepared_callback_count, .acquire) != 1)
        proof.fail("SMP transport canceled owner executed");
    runtime.collectExecution(canceled) catch proof.fail("SMP transport canceled collection");
    verifyTransportRetained(runtime, source, task, handle, admitted);

    // Only the real yield callback changed the cached context. STOP and both
    // cancellation paths never entered user-context preparation or the root.
    prepared_owner_expectation.user_context.rax = 1;
    prepared_owner_expectation.user_context.rdx = returned.ui_revision;
    prepared_owner_expectation.user_context.rsi = @backingInt(@import("../../native/task/userspace_bootstrap_mailbox.zig").YieldDisposition.runnable);
    prepared_owner_expectation.user_context.instruction_pointer += 4;
    prepared_owner_expectation.receipt = .{
        .outcome = .faulted,
        .fault_vector = 14,
        .fault_error_code = 0x8000_0027,
        .fault_instruction_pointer = 0x4000_2345,
        .fault_address = 0x4000_6789,
    };
    const faulted = publishTransportEpoch(runtime, source, task, handle, &command);
    @atomicStore(u32, &transport_phase, 4, .release);
    waitForTransportWord(&transport_returned, 4);
    verifyTransportReturned(runtime, source, faulted, admitted);
    if (@atomicLoad(u32, &prepared_callback_count, .acquire) != 2 or prepared_xstate_address == 0 or
        !(runtime.terminateTask(task_id, 910) catch proof.fail("SMP transport deferred termination")))
        proof.fail("SMP transport fault callback lifetime");
    runtime.execution.consumePreparedReturnInto(faulted, &returned) catch proof.fail("SMP transport fault receipt");
    if (!std.meta.eql(returned, prepared_owner_expectation.receipt)) proof.fail("SMP transport fault scalars");
    rejectRepeatedPreparedConsume(runtime, faulted);
    rejectTransportCollection(runtime, scheduler, source, faulted, address_space_id, admitted);
    if (task.state != .terminated or task.execution_component_count != 1) proof.fail("SMP transport early task retirement");
    @atomicStore(u32, &transport_released, 4, .release);
    verifyTransportCompletion(4, .owner_returned);
    runtime.collectExecution(faulted) catch proof.fail("SMP transport fault collection");
    if (!native_executor.collectRegisteredRetiredMappings(scheduler, runtime) or source.materializedCount() != 0 or
        source.mappingHandle(address_space_id) != null or runtime.findAddressSpaceConst(address_space_id) != null or
        task.execution_component_count != 0 or preparedBorrowCount(runtime) != 0 or runtime.execution.hasLeases() or
        dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution) or paging.frameStats().allocated != admitted - 1)
        proof.fail("SMP transport exact root retirement");
    if (runtime.collectExecution(faulted)) |_| proof.fail("SMP transport repeated root retirement") else |err| {
        if (err != error.StaleTicket or paging.frameStats().allocated != admitted - 1)
            proof.fail("SMP transport repeated collection changed resources");
    }

    const replacement = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 204 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 1, .memory_bytes = 0, .endpoint_slots = 0, .shared_memory_bytes = 0 },
        .local_only = true,
    }) catch proof.fail("SMP transport replacement task");
    const replacement_ticket = runtime.reserveExecution(replacement, PREPARED_OWNER_CPU) catch proof.fail("SMP transport replacement reservation");
    if (replacement_ticket.issuer != first.issuer or replacement_ticket.epoch <= faulted.epoch)
        proof.fail("SMP transport replacement identity");
    @atomicStore(u32, &transport_phase, 5, .release);
    waitForTransportWord(&transport_completed, 5);
    if ((runtime.execution.phase(replacement_ticket) catch proof.fail("SMP transport replacement phase")) != .reserved or
        !runtime.execution.hasLeaseForTask(replacement.id) or preparedBorrowCount(runtime) != 1 or source.materializedCount() != 0 or
        @atomicLoad(u32, &prepared_callback_count, .acquire) != 2 or paging.frameStats().allocated != admitted - 1)
        proof.fail("SMP transport stale claim changed replacement");
    runtime.cancelUnstartedExecution(replacement_ticket) catch proof.fail("SMP transport replacement cancellation");
    runtime.collectExecution(replacement_ticket) catch proof.fail("SMP transport replacement collection");
    if (!(runtime.terminateTask(replacement.id, 911) catch proof.fail("SMP transport replacement retirement")))
        proof.fail("SMP transport replacement termination");
    scheduler.deinit();
    for ([_]*native_executor.Executor{ anchor, source }) |executor| {
        if (executor.registration_cpu != null or executor.binding_owner != null or executor.bound_runtime != null or
            executor.materializedCount() != 0) proof.fail("SMP transport drained domain");
        table_backing.free(native_executor.Executor, executor);
    }
    table_backing.free(native_scheduler.Scheduler, scheduler);
    verifyPreparedNeighbors();
    if (preparedBorrowCount(runtime) != 0 or runtime.execution.hasLeases() or
        dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution) or paging.frameStats().allocated != admitted - 1 or
        !paging.kernelAddressSpaceActive() or x86.readCr3() != bsp_cr3 or x86.interruptsEnabled())
        proof.fail("SMP transport final ownership");
    @atomicStore(u32, &transport_phase, PREPARED_TRANSPORT_DONE, .release);
    proof.pass("SMP_AP_TRANSPORT");
}

fn publishTransportEpoch(runtime: *task_runtime.Runtime, source: *native_executor.Executor, task: *task_runtime.TaskRecord, handle: native_executor.MappingHandle, command: *native_executor.ArchitecturePreparedCommand) dispatch_ownership.Ticket {
    const ticket = runtime.reserveExecution(task, PREPARED_OWNER_CPU) catch proof.fail("SMP transport reservation");
    if (!source.bindPreparedExecutionForArchitectureProof(task, handle, ticket, command) or
        !source.publishPreparedExecutionForArchitectureProof(command, &transport_key)) proof.fail("SMP transport publication");
    return ticket;
}

fn waitForTransportWord(word: *const u32, phase: u32) void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    while (@atomicLoad(u32, word, .acquire) != phase) {
        if (deadline.expired() or @atomicLoad(u8, &cpus[PREPARED_OWNER_CPU].status, .acquire) != 1)
            proof.fail("SMP transport phase timeout");
        asm volatile ("pause");
    }
}

fn verifyTransportReturned(runtime: *task_runtime.Runtime, source: *native_executor.Executor, ticket: dispatch_ownership.Ticket, admitted: usize) void {
    if (!transport_owner_ran or preparedBorrowCount(runtime) != 1 or !runtime.execution.hasLeaseForTask(prepared_owner_expectation.task_id) or
        (runtime.execution.phase(ticket) catch proof.fail("SMP transport returned phase")) != .returned or
        source.active_task_id != 0 or source.active_mapping != null or source.active_dispatch_lease != null or
        !std.meta.eql(source.dispatch_quantum, native_executor.DispatchQuantum{}) or source.materializedCount() != 1 or
        paging.frameStats().allocated != admitted or !paging.kernelAddressSpaceActive() or x86.interruptsEnabled())
        proof.fail("SMP transport returned ownership");
    var completion: dispatch_transport.Completion = .unstarted;
    if (dispatch_transport.global.completionInto(transport_key, &completion)) |_| proof.fail("SMP transport completed before hold release") else |err| {
        if (err != error.WrongPhase or completion != .unstarted) proof.fail("SMP transport incomplete query changed output");
    }
    verifyPreparedNeighbors();
}

fn rejectTransportCollection(runtime: *task_runtime.Runtime, scheduler: *native_scheduler.Scheduler, source: *native_executor.Executor, ticket: dispatch_ownership.Ticket, address_space_id: u64, admitted: usize) void {
    if (runtime.collectExecution(ticket)) |_| proof.fail("SMP transport collected before static completion") else |err| {
        if (err != error.Busy) proof.fail("SMP transport collection refusal error");
    }
    if (native_executor.releaseRegisteredDomain(scheduler, runtime) or preparedBorrowCount(runtime) != 1 or
        !runtime.execution.hasLeaseForTask(prepared_owner_expectation.task_id) or source.materializedCount() != 1 or
        runtime.findAddressSpaceConst(address_space_id) == null or paging.frameStats().allocated != admitted)
        proof.fail("SMP transport hold released domain resources");
}

fn verifyTransportCompletion(phase: u32, expected: dispatch_transport.Completion) void {
    waitForTransportWord(&transport_completed, phase);
    var completion: dispatch_transport.Completion = undefined;
    dispatch_transport.global.completionInto(transport_key, &completion) catch proof.fail("SMP transport completion receipt");
    if (completion != expected) proof.fail("SMP transport completion kind");
    verifyPreparedNeighbors();
}

fn verifyTransportRetained(runtime: *task_runtime.Runtime, source: *native_executor.Executor, task: *const task_runtime.TaskRecord, handle: native_executor.MappingHandle, admitted: usize) void {
    if (preparedBorrowCount(runtime) != 0 or runtime.execution.hasLeases() or
        dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution) or source.materializedCount() != 1 or
        !source.mappingHandle(task.address_space_id).?.eql(handle) or task.state != .active or task.execution_component_count != 1 or
        runtime.findAddressSpaceConst(task.address_space_id) == null or paging.frameStats().allocated != admitted)
        proof.fail("SMP transport canceled mapping lifetime");
}

fn consumeTransportUnavailable(runtime: *task_runtime.Runtime, ticket: dispatch_ownership.Ticket) void {
    var returned: dispatch_ownership.ReturnRecord = undefined;
    runtime.execution.consumePreparedReturnInto(ticket, &returned) catch proof.fail("SMP transport unavailable receipt");
    if (!std.meta.eql(returned, dispatch_ownership.ReturnRecord{})) proof.fail("SMP transport canceled receipt scalars");
    rejectRepeatedPreparedConsume(runtime, ticket);
}

fn transportBeforeRun(context: *anyopaque) void {
    if (context != @as(*anyopaque, @ptrCast(&transport_owner_phase))) proof.fail("SMP transport hook context");
    const phase = transport_owner_phase;
    @atomicStore(u32, &transport_claimed, phase, .release);
    if (phase == 3) waitForTransportWord(&transport_released, phase);
}

fn transportAfterReturn(context: *anyopaque, ran: bool) void {
    // Everything below is permanent guest storage or captured scalar state.
    // No task/domain/command/issuer pointer may be read after the runner ACK.
    if (context != @as(*anyopaque, @ptrCast(&transport_owner_phase))) proof.fail("SMP transport return hook context");
    const phase = transport_owner_phase;
    transport_owner_ran = ran;
    @atomicStore(u32, &transport_returned, phase, .release);
    if (phase == 1 or phase == 4) waitForTransportWord(&transport_released, phase);
}

fn holdPreparedTransport(index: u8) void {
    if (index != PREPARED_OWNER_CPU) return;
    const saved_entry = native_entry.current().*;
    const assigned_top = native_executor.preparedKernelStackForCpu(index) orelse reject(index);
    if (assigned_top != cpus[index].trap_stack_top or saved_entry.native_entry_modes != 0 or x86.interruptsEnabled()) reject(index);
    for (1..PREPARED_TRANSPORT_DONE) |phase| {
        waitForTransportWord(&transport_phase, @intCast(phase));
        transport_owner_phase = @intCast(phase);
        if (phase == 5) {
            var claimed = transport_claim_canary;
            if (dispatch_transport.global.claimKeyInto(transport_stale_key, &claimed)) |_| {
                proof.fail("SMP transport stale owner claimed");
            } else |err| if (err != error.StaleKey) proof.fail("SMP transport stale claim error");
            if (!std.meta.eql(claimed, transport_claim_canary)) proof.fail("SMP transport stale claim mutated output");
        } else {
            _ = native_entry.initializeCpu(index, assigned_top);
            if (!native_executor.runQueuedPreparedExecutionForArchitectureProof(
                preparedOwnerCallback,
                &prepared_owner_expectation,
                &saved_entry,
                transportBeforeRun,
                transportAfterReturn,
                &transport_owner_phase,
            )) reject(index);
        }
        // The wrapper has already restored GS and published control-only
        // completion. No cold command, source, task or root is consulted here.
        @atomicStore(u32, &transport_completed, @intCast(phase), .release);
    }
    waitForTransportWord(&transport_phase, PREPARED_TRANSPORT_DONE);
}

// A real fixed IPI, independently observed after its standard-xstate IRET
// gate, now prompts the durable claim. Native entry modes remain zero; this
// proves interrupt-driven CPL0 delivery rather than AP userspace admission.
fn provePromptedPreparedTransport(runtime: *task_runtime.Runtime) void {
    if (cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or
        runtime.execution.hasLeases() or preparedBorrowCount(runtime) != 0 or
        dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution)) proof.fail("SMP prompted fixture owner");
    const bsp_cr3 = x86.readCr3();
    const anchor = table_backing.alloc(native_executor.Executor) orelse proof.fail("SMP prompted anchor allocation");
    anchor.* = .{};
    const source = table_backing.alloc(native_executor.Executor) orelse proof.fail("SMP prompted source allocation");
    source.* = .{};
    const scheduler = table_backing.alloc(native_scheduler.Scheduler) orelse proof.fail("SMP prompted Scheduler allocation");
    scheduler.initializeAllocated(anchor);
    if (!native_scheduler.ArchitectureProof.bindDomain(scheduler, runtime) or
        !source.claimRuntimeBinding(scheduler, runtime) or
        !source.claimMappingRegistration(PREPARED_OWNER_CPU, scheduler, runtime)) proof.fail("SMP prompted domain binding");
    const task = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 205 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = PAGE_BYTES, .endpoint_slots = 0, .shared_memory_bytes = 0 },
        .initial_component = .{ .label = "prepared-ipi", .entry = "prepared-ipi" },
        .local_only = true,
    }) catch proof.fail("SMP prompted task creation");
    const task_id = task.id;
    const address_space_id = task.address_space_id;
    var context = prepared_owner_expectation.user_context;
    context.rax = 0xb123_4567_89ab_cdef;
    context.instruction_pointer = 0x4000_3000;
    const before_root = paging.frameStats().allocated;
    const space = paging.createUserAddressSpace() catch proof.fail("SMP prompted root allocation");
    if (paging.frameStats().allocated != before_root + 1) proof.fail("SMP prompted root accounting");
    var handle: native_executor.MappingHandle = undefined;
    if (!source.installPreparedExecutionMappingForArchitectureProof(task, space, context, &handle))
        proof.fail("SMP prompted mapping installation");
    const admitted = paging.frameStats().allocated;
    for (&prepared_neighbors, 0..) |*snapshot, cpu| {
        snapshot.* = native_entry.stateForCpu(@intCast(cpu)).*;
        if (snapshot.native_entry_modes != 0) proof.fail("SMP prompted native entry admission");
    }
    prepared_xstate_address = 0;
    @atomicStore(u32, &prepared_callback_count, 0, .monotonic);
    prepared_owner_expectation = .{
        .task_id = task_id,
        .physical_root = space.switch_cr3 & x86.CR3_ADDRESS_MASK,
        .user_context = context,
        .receipt = .{ .outcome = .yielded, .ui_revision = 0x369c_147a_cdef_2468 },
    };
    var command: native_executor.ArchitecturePreparedCommand = undefined;
    const first = publishPromptedEpoch(runtime, source, task, handle, &command);
    const first_key = prompted_key;
    @atomicStore(u32, &prompted_phase, 1, .release);
    waitForTransportWord(&prompted_checked, 1);
    if (@atomicLoad(u32, &prompted_ipi_count, .acquire) != 0 or
        @atomicLoad(u32, &prepared_callback_count, .acquire) != 0 or
        (runtime.execution.phase(first) catch proof.fail("SMP prompted no-hint phase")) != .ready or
        preparedBorrowCount(runtime) != 1 or source.materializedCount() != 1 or paging.frameStats().allocated != admitted)
        proof.fail("SMP prompted pending command changed without IPI");
    var completion: dispatch_transport.Completion = .unstarted;
    if (dispatch_transport.global.completionInto(first_key, &completion)) |_| proof.fail("SMP prompted no-hint completed") else |err| {
        if (err != error.WrongPhase or completion != .unstarted) proof.fail("SMP prompted no-hint query changed output");
    }
    verifyPreparedNeighbors();

    // The selected AP still has IF clear until phase 2 is acquired. The fixed
    // vector is pending before its first finite standard-xstate IPI window.
    if (!smp.notifyPreparedExecution(PREPARED_OWNER_CPU)) proof.fail("SMP prompted pending-before-IF notification");
    @atomicStore(u32, &prompted_phase, 2, .release);
    waitForTransportWord(&prompted_returned, 2);
    verifyPromptedReturn(runtime, source, first, admitted, 1);
    var returned: dispatch_ownership.ReturnRecord = undefined;
    runtime.execution.consumePreparedReturnInto(first, &returned) catch proof.fail("SMP prompted yield receipt");
    if (!std.meta.eql(returned, prepared_owner_expectation.receipt)) proof.fail("SMP prompted yield scalars");
    rejectRepeatedPreparedConsume(runtime, first);
    rejectTransportCollection(runtime, scheduler, source, first, address_space_id, admitted);
    @atomicStore(u32, &prompted_released, 2, .release);
    verifyPromptedCompletion(2);
    runtime.collectExecution(first) catch proof.fail("SMP prompted yield collection");
    verifyTransportRetained(runtime, source, task, handle, admitted);

    // Fixed vectors coalesce. Two prompts of an empty channel must never
    // re-execute the first command or create a second completion/return.
    if (!smp.notifyPreparedExecution(PREPARED_OWNER_CPU) or !smp.notifyPreparedExecution(PREPARED_OWNER_CPU))
        proof.fail("SMP prompted duplicate empty notification");
    @atomicStore(u32, &prompted_phase, 3, .release);
    waitForTransportWord(&prompted_completed, 3);
    if (@atomicLoad(u32, &prepared_callback_count, .acquire) != 1) proof.fail("SMP prompted duplicate executed");
    verifyTransportRetained(runtime, source, task, handle, admitted);
    verifyPreparedNeighbors();

    prepared_owner_expectation.user_context.rax = 1;
    prepared_owner_expectation.user_context.rdx = returned.ui_revision;
    prepared_owner_expectation.user_context.rsi = @backingInt(@import("../../native/task/userspace_bootstrap_mailbox.zig").YieldDisposition.runnable);
    prepared_owner_expectation.user_context.instruction_pointer += 4;
    prepared_owner_expectation.receipt = .{
        .outcome = .faulted,
        .fault_vector = 14,
        .fault_error_code = 0x8000_0037,
        .fault_instruction_pointer = 0x4000_3456,
        .fault_address = 0x4000_789a,
    };
    const second = publishPromptedEpoch(runtime, source, task, handle, &command);
    completion = .owner_returned;
    if (second.epoch <= first.epoch or prompted_key.sequence <= first_key.sequence) proof.fail("SMP prompted replacement sequence");
    if (dispatch_transport.global.completionInto(first_key, &completion)) |_| proof.fail("SMP prompted stale completion accepted") else |err| {
        if (err != error.StaleKey or completion != .owner_returned) proof.fail("SMP prompted stale completion changed output");
    }
    @atomicStore(u32, &zigos_arch_smp_prepared_ipi_window, 0, .release);
    @atomicStore(u32, &prompted_phase, 4, .release);
    // Assembly publishes this witness after STI without changing any seeded
    // GPR. Only finite windows enable IF; the local timer remains masked.
    waitForTransportWord(&zigos_arch_smp_prepared_ipi_window, 1);
    if (!smp.notifyPreparedExecution(PREPARED_OWNER_CPU)) proof.fail("SMP prompted during-window notification");
    waitForTransportWord(&prompted_returned, 4);
    verifyPromptedReturn(runtime, source, second, admitted, 2);
    if (prepared_xstate_address == 0 or !(runtime.terminateTask(task_id, 920) catch proof.fail("SMP prompted deferred termination")) or
        task.state != .terminated or task.execution_component_count != 1) proof.fail("SMP prompted fault lifetime");
    runtime.execution.consumePreparedReturnInto(second, &returned) catch proof.fail("SMP prompted fault receipt");
    if (!std.meta.eql(returned, prepared_owner_expectation.receipt)) proof.fail("SMP prompted fault scalars");
    rejectRepeatedPreparedConsume(runtime, second);
    rejectTransportCollection(runtime, scheduler, source, second, address_space_id, admitted);
    @atomicStore(u32, &prompted_released, 4, .release);
    verifyPromptedCompletion(4);
    runtime.collectExecution(second) catch proof.fail("SMP prompted fault collection");
    if (!native_executor.collectRegisteredRetiredMappings(scheduler, runtime) or source.materializedCount() != 0 or
        source.mappingHandle(address_space_id) != null or runtime.findAddressSpaceConst(address_space_id) != null or
        task.execution_component_count != 0 or preparedBorrowCount(runtime) != 0 or runtime.execution.hasLeases() or
        dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution) or paging.frameStats().allocated != admitted - 1)
        proof.fail("SMP prompted exact root retirement");
    if (runtime.collectExecution(second)) |_| proof.fail("SMP prompted duplicate root retirement") else |err| {
        if (err != error.StaleTicket or paging.frameStats().allocated != admitted - 1)
            proof.fail("SMP prompted repeated collection changed frames");
    }

    const replacement = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 206 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 1, .memory_bytes = 0, .endpoint_slots = 0, .shared_memory_bytes = 0 },
        .local_only = true,
    }) catch proof.fail("SMP prompted replacement task");
    const replacement_ticket = runtime.reserveExecution(replacement, PREPARED_OWNER_CPU) catch proof.fail("SMP prompted replacement reservation");
    if (replacement_ticket.issuer != first.issuer or replacement_ticket.epoch <= second.epoch)
        proof.fail("SMP prompted replacement identity");
    // A delayed old hint has no command/epoch authority. Even with a newer
    // live reservation, an empty channel cannot execute or acknowledge it.
    if (!smp.notifyPreparedExecution(PREPARED_OWNER_CPU)) proof.fail("SMP prompted stale hint notification");
    @atomicStore(u32, &prompted_phase, 5, .release);
    waitForTransportWord(&prompted_completed, 5);
    if ((runtime.execution.phase(replacement_ticket) catch proof.fail("SMP prompted replacement phase")) != .reserved or
        !runtime.execution.hasLeaseForTask(replacement.id) or preparedBorrowCount(runtime) != 1 or source.materializedCount() != 0 or
        @atomicLoad(u32, &prepared_callback_count, .acquire) != 2 or paging.frameStats().allocated != admitted - 1)
        proof.fail("SMP prompted stale hint changed replacement");
    const deliveries = @atomicLoad(u32, &prompted_ipi_count, .acquire);
    if (deliveries < 4 or deliveries > 5) proof.fail("SMP prompted interrupt receipt count");
    runtime.cancelUnstartedExecution(replacement_ticket) catch proof.fail("SMP prompted replacement cancellation");
    runtime.collectExecution(replacement_ticket) catch proof.fail("SMP prompted replacement collection");
    if (!(runtime.terminateTask(replacement.id, 921) catch proof.fail("SMP prompted replacement retirement")))
        proof.fail("SMP prompted replacement termination");
    scheduler.deinit();
    for ([_]*native_executor.Executor{ anchor, source }) |executor| {
        if (executor.registration_cpu != null or executor.binding_owner != null or executor.bound_runtime != null or
            executor.materializedCount() != 0) proof.fail("SMP prompted drained domain");
        table_backing.free(native_executor.Executor, executor);
    }
    table_backing.free(native_scheduler.Scheduler, scheduler);
    verifyPreparedNeighbors();
    if (preparedBorrowCount(runtime) != 0 or runtime.execution.hasLeases() or
        dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution) or paging.frameStats().allocated != admitted - 1 or
        !paging.kernelAddressSpaceActive() or x86.readCr3() != bsp_cr3 or x86.interruptsEnabled())
        proof.fail("SMP prompted final ownership");
    @atomicStore(u32, &prompted_phase, PREPARED_IPI_DONE, .release);
    proof.pass("SMP_AP_TRANSPORT_IPI");
}

fn publishPromptedEpoch(runtime: *task_runtime.Runtime, source: *native_executor.Executor, task: *task_runtime.TaskRecord, handle: native_executor.MappingHandle, command: *native_executor.ArchitecturePreparedCommand) dispatch_ownership.Ticket {
    const ticket = runtime.reserveExecution(task, PREPARED_OWNER_CPU) catch proof.fail("SMP prompted reservation");
    if (!source.bindPreparedExecutionForArchitectureProof(task, handle, ticket, command) or
        !source.publishPreparedExecutionForArchitectureProof(command, &prompted_key)) proof.fail("SMP prompted publication");
    return ticket;
}

fn verifyPromptedReturn(runtime: *task_runtime.Runtime, source: *native_executor.Executor, ticket: dispatch_ownership.Ticket, admitted: usize, callback_count: u32) void {
    if (!prompted_owner_ran or @atomicLoad(u32, &prepared_callback_count, .acquire) != callback_count or
        preparedBorrowCount(runtime) != 1 or !runtime.execution.hasLeaseForTask(prepared_owner_expectation.task_id) or
        (runtime.execution.phase(ticket) catch proof.fail("SMP prompted returned phase")) != .returned or
        source.active_task_id != 0 or source.active_mapping != null or source.active_dispatch_lease != null or
        !std.meta.eql(source.dispatch_quantum, native_executor.DispatchQuantum{}) or source.materializedCount() != 1 or
        paging.frameStats().allocated != admitted or !paging.kernelAddressSpaceActive() or x86.interruptsEnabled())
        proof.fail("SMP prompted returned ownership");
    var completion: dispatch_transport.Completion = .unstarted;
    if (dispatch_transport.global.completionInto(prompted_key, &completion)) |_| proof.fail("SMP prompted completed before release") else |err| {
        if (err != error.WrongPhase or completion != .unstarted) proof.fail("SMP prompted incomplete output changed");
    }
    verifyPreparedNeighbors();
}

fn verifyPromptedCompletion(phase: u32) void {
    waitForTransportWord(&prompted_completed, phase);
    var completion: dispatch_transport.Completion = .unstarted;
    dispatch_transport.global.completionInto(prompted_key, &completion) catch proof.fail("SMP prompted completion receipt");
    if (completion != .owner_returned) proof.fail("SMP prompted completion kind");
    verifyPreparedNeighbors();
}

fn promptedAfterReturn(context: *anyopaque, ran: bool) void {
    // Execution ACK already ended all source/command/issuer accesses. Only
    // permanent static hook data and the copied scalar result remain here.
    if (context != @as(*anyopaque, @ptrCast(&prompted_owner_phase))) proof.fail("SMP prompted hook context");
    const phase = prompted_owner_phase;
    prompted_owner_ran = ran;
    @atomicStore(u32, &prompted_returned, phase, .release);
    waitForTransportWord(&prompted_released, phase);
}

fn waitForPreparedPrompt(index: u8, previous: u32, saved_entry: *const native_entry.State) u32 {
    const deadline = tsc_clock.afterMilliseconds(2000);
    const cpu = &cpus[index];
    while (true) {
        model.initialize(&cpu.seed, index % 3);
        model.initializeCanary(&cpu.restored);
        var restored_flags: usize = 0;
        const gp_match = zigos_arch_smp_poll_prepared_ipi(&cpu.seed, &cpu.restored, &restored_flags);
        const observed = native_entry.current().*;
        if (gp_match != 1 or restored_flags & (FLAG_DF | FLAG_AC) != FLAG_DF | FLAG_AC or
            !verifyRestoredState(&cpu.seed, &cpu.restored) or x86.interruptsEnabled() or
            !paging.kernelAddressSpaceActive() or x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3 or
            !std.mem.eql(u8, std.mem.asBytes(&observed), std.mem.asBytes(saved_entry))) reject(index);
        // This independent release receipt came from the real EOI+prompt
        // handler and is acquired only after its IRET and hardware restoration.
        const delivered = @atomicLoad(u32, &prompted_ipi_count, .acquire);
        if (delivered > previous) return delivered;
        if (delivered < previous or deadline.expired()) proof.fail("SMP prompted finite IPI timeout");
    }
}

fn rejectPromptedEmpty(index: u8, saved_entry: *const native_entry.State) void {
    if (native_executor.runPromptedPreparedExecutionForArchitectureProof(
        preparedOwnerCallback,
        &prepared_owner_expectation,
        saved_entry,
        null,
        null,
        &prompted_owner_phase,
    )) reject(index);
    const observed = native_entry.current().*;
    if (!std.mem.eql(u8, std.mem.asBytes(&observed), std.mem.asBytes(saved_entry)) or
        !paging.kernelAddressSpaceActive() or x86.interruptsEnabled()) reject(index);
}

fn holdPromptedPreparedTransport(index: u8) void {
    if (index != PREPARED_OWNER_CPU) return;
    const saved_entry = native_entry.current().*;
    const assigned_top = native_executor.preparedKernelStackForCpu(index) orelse reject(index);
    if (assigned_top != cpus[index].trap_stack_top or saved_entry.native_entry_modes != 0 or x86.interruptsEnabled()) reject(index);
    waitForTransportWord(&prompted_phase, 1);
    rejectPromptedEmpty(index, &saved_entry);
    rejectPromptedEmpty(index, &saved_entry);
    @atomicStore(u32, &prompted_checked, 1, .release);
    var delivered: u32 = 0;
    for (2..PREPARED_IPI_DONE) |phase| {
        waitForTransportWord(&prompted_phase, @intCast(phase));
        prompted_owner_phase = @intCast(phase);
        delivered = waitForPreparedPrompt(index, delivered, &saved_entry);
        if (phase == 2 or phase == 4) {
            _ = native_entry.initializeCpu(index, assigned_top);
            if (!native_executor.runPromptedPreparedExecutionForArchitectureProof(
                preparedOwnerCallback,
                &prepared_owner_expectation,
                &saved_entry,
                null,
                promptedAfterReturn,
                &prompted_owner_phase,
            )) reject(index);
        } else {
            rejectPromptedEmpty(index, &saved_entry);
            rejectPromptedEmpty(index, &saved_entry);
        }
        // Static completion already ended the runner; no domain/source/task
        // or command reads are permitted while the BSP may retire them.
        @atomicStore(u32, &prompted_completed, @intCast(phase), .release);
    }
    waitForTransportWord(&prompted_phase, PREPARED_IPI_DONE);
}

// A manual CPL0 switch uses the actual guarded CPU1 backing and unchanged
// production kernel-origin ISR116/common stub. It does not exercise TSS RSP0,
// IST/FRED delivery, compacted state or native AP userspace admission.
fn proveGuardedTrapStack(runtime: *task_runtime.Runtime) void {
    if (cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or
        runtime.execution.hasLeases() or preparedBorrowCount(runtime) != 0 or
        dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution)) proof.fail("SMP guarded stack fixture owner");
    @atomicStore(u8, &trap_stack_quiescent[0], 1, .release);
    const quiet_deadline = tsc_clock.afterMilliseconds(2000);
    for (trap_stack_quiescent[1..], 1..) |*quiet, cpu| {
        while (@atomicLoad(u8, quiet, .acquire) != 1) {
            if (@atomicLoad(u8, &cpus[cpu].status, .acquire) != 1 or quiet_deadline.expired())
                proof.fail("SMP guarded stack IF0 rendezvous");
            asm volatile ("pause");
        }
    }
    const bsp_cr3 = x86.readCr3();
    const anchor = table_backing.alloc(native_executor.Executor) orelse proof.fail("SMP guarded stack anchor allocation");
    anchor.* = .{};
    const source = table_backing.alloc(native_executor.Executor) orelse proof.fail("SMP guarded stack source allocation");
    source.* = .{};
    const scheduler = table_backing.alloc(native_scheduler.Scheduler) orelse proof.fail("SMP guarded stack Scheduler allocation");
    scheduler.initializeAllocated(anchor);
    if (!native_scheduler.ArchitectureProof.bindDomain(scheduler, runtime) or
        !source.claimRuntimeBinding(scheduler, runtime) or
        !source.claimMappingRegistration(PREPARED_OWNER_CPU, scheduler, runtime)) proof.fail("SMP guarded stack domain binding");
    const task = runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 207 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = PAGE_BYTES, .endpoint_slots = 0, .shared_memory_bytes = 0 },
        .initial_component = .{ .label = "guarded-stack", .entry = "guarded-stack" },
        .local_only = true,
    }) catch proof.fail("SMP guarded stack task creation");
    const task_id = task.id;
    const address_space_id = task.address_space_id;
    var context = prepared_owner_expectation.user_context;
    context.rax = 0xc123_4567_89ab_cdef;
    context.instruction_pointer = 0x4000_5000;
    const before_root = paging.frameStats().allocated;
    const space = paging.createUserAddressSpace() catch proof.fail("SMP guarded stack root allocation");
    if (paging.frameStats().allocated != before_root + 1) proof.fail("SMP guarded stack root accounting");
    var handle: native_executor.MappingHandle = undefined;
    if (!source.installPreparedExecutionMappingForArchitectureProof(task, space, context, &handle))
        proof.fail("SMP guarded stack mapping installation");
    const admitted = paging.frameStats().allocated;
    for (&prepared_neighbors, 0..) |*snapshot, cpu| {
        snapshot.* = native_entry.stateForCpu(@intCast(cpu)).*;
        if (snapshot.native_entry_modes != 0) proof.fail("SMP guarded stack native entry admission");
    }
    prepared_xstate_address = 0;
    @atomicStore(u32, &prepared_callback_count, 0, .monotonic);
    prepared_owner_expectation = .{
        .task_id = task_id,
        .physical_root = space.switch_cr3 & x86.CR3_ADDRESS_MASK,
        .user_context = context,
        .receipt = .{ .outcome = .yielded, .ui_revision = 0x57ac_147a_cdef_2468 },
    };
    var command: native_executor.ArchitecturePreparedCommand = undefined;
    const ticket = runtime.reserveExecution(task, PREPARED_OWNER_CPU) catch proof.fail("SMP guarded stack reservation");
    if (!source.bindPreparedExecutionForArchitectureProof(task, handle, ticket, &command) or
        !source.publishPreparedExecutionForArchitectureProof(&command, &trap_stack_key)) proof.fail("SMP guarded stack publication");
    verifyGuardedTrapAuthority(PREPARED_OWNER_CPU);
    verifyGuardedStackNeighbors();
    const saved_gate = idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR];
    idt.setGate(smp.PREPARED_EXECUTION_IPI_VECTOR, &isr116, gdt.KERNEL_CODE_SEG, 0x8e);
    verifyGuardedStackGate();
    asm volatile ("mfence" ::: .{ .memory = true });
    @atomicStore(u32, &trap_stack_phase, 1, .release);
    waitForTransportWord(&trap_stack_checked, 1);
    if ((runtime.execution.phase(ticket) catch proof.fail("SMP guarded stack no-hint phase")) != .ready or
        @atomicLoad(u32, &prepared_callback_count, .acquire) != 0 or source.active_mapping != null or
        paging.frameStats().allocated != admitted or trap_stack_baseline_low == 0)
        proof.fail("SMP guarded stack baseline claimed command");
    verifyPreparedNeighbors();
    verifyGuardedStackNeighbors();

    // All CPUs remain IF0. This one real vector is pending before the selected
    // AP opens its finite window on the guarded stack through actual ISR116.
    if (!smp.notifyPreparedExecution(PREPARED_OWNER_CPU)) proof.fail("SMP guarded stack notification");
    @atomicStore(u32, &trap_stack_phase, 2, .release);
    waitForTransportWord(&trap_stack_checked, 2);
    if (trap_stack_interrupt_low < cpus[PREPARED_OWNER_CPU].trap_stack_top - native_executor.TRAP_STACK_USABLE_BYTES + PAGE_BYTES or
        trap_stack_interrupt_low >= trap_stack_baseline_low or
        trap_stack_baseline_low - trap_stack_interrupt_low < xstate.image_bytes)
        proof.fail("SMP guarded stack actual ISR depth");
    verifyGuardedTrapAuthority(PREPARED_OWNER_CPU);
    verifyPreparedNeighbors();
    verifyGuardedStackNeighbors();
    verifyGuardedStackGate();
    // The acquire above witnesses CPU1's CLI return to its ordinary stack.
    // Every other CPU is still waiting IF0, so restore the complete saved gate.
    idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR] = saved_gate;
    asm volatile ("mfence" ::: .{ .memory = true });
    if (@as(u128, @bitCast(idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR])) != @as(u128, @bitCast(saved_gate)))
        proof.fail("SMP guarded stack complete IDT restoration");
    @atomicStore(u32, &trap_stack_phase, 3, .release);
    waitForTransportWord(&trap_stack_returned, 1);
    if (!trap_stack_owner_ran or @atomicLoad(u32, &prepared_callback_count, .acquire) != 1 or
        (runtime.execution.phase(ticket) catch proof.fail("SMP guarded stack returned phase")) != .returned or
        preparedBorrowCount(runtime) != 1 or source.materializedCount() != 1 or
        source.active_task_id != 0 or source.active_mapping != null or source.active_dispatch_lease != null or
        !std.meta.eql(source.dispatch_quantum, native_executor.DispatchQuantum{}) or paging.frameStats().allocated != admitted)
        proof.fail("SMP guarded stack returned ownership");
    var returned: dispatch_ownership.ReturnRecord = undefined;
    runtime.execution.consumePreparedReturnInto(ticket, &returned) catch proof.fail("SMP guarded stack receipt");
    if (!std.meta.eql(returned, prepared_owner_expectation.receipt)) proof.fail("SMP guarded stack yielded scalars");
    rejectRepeatedPreparedConsume(runtime, ticket);
    if (!(runtime.terminateTask(task_id, 922) catch proof.fail("SMP guarded stack deferred termination")) or
        task.state != .terminated or task.execution_component_count != 1 or prepared_xstate_address == 0)
        proof.fail("SMP guarded stack retained task lifetime");
    rejectTransportCollection(runtime, scheduler, source, ticket, address_space_id, admitted);
    @atomicStore(u32, &trap_stack_released, 1, .release);
    waitForTransportWord(&trap_stack_completed, 1);
    var completion: dispatch_transport.Completion = .unstarted;
    dispatch_transport.global.completionInto(trap_stack_key, &completion) catch proof.fail("SMP guarded stack static completion");
    if (completion != .owner_returned) proof.fail("SMP guarded stack completion kind");
    runtime.collectExecution(ticket) catch proof.fail("SMP guarded stack collection");
    if (!native_executor.collectRegisteredRetiredMappings(scheduler, runtime) or source.materializedCount() != 0 or
        source.mappingHandle(address_space_id) != null or runtime.findAddressSpaceConst(address_space_id) != null or
        task.execution_component_count != 0 or preparedBorrowCount(runtime) != 0 or runtime.execution.hasLeases() or
        dispatch_transport.global.hasOutstandingForIssuer(&runtime.execution) or paging.frameStats().allocated != admitted - 1)
        proof.fail("SMP guarded stack exact root retirement");
    if (runtime.collectExecution(ticket)) |_| proof.fail("SMP guarded stack duplicate retirement") else |err| {
        if (err != error.StaleTicket or paging.frameStats().allocated != admitted - 1)
            proof.fail("SMP guarded stack repeated collection changed frames");
    }
    scheduler.deinit();
    for ([_]*native_executor.Executor{ anchor, source }) |executor| {
        if (executor.registration_cpu != null or executor.binding_owner != null or executor.bound_runtime != null or
            executor.materializedCount() != 0) proof.fail("SMP guarded stack drained domain");
        table_backing.free(native_executor.Executor, executor);
    }
    table_backing.free(native_scheduler.Scheduler, scheduler);
    verifyPreparedNeighbors();
    verifyGuardedStackNeighbors();
    if (paging.frameStats().allocated != admitted - 1 or !paging.kernelAddressSpaceActive() or
        x86.readCr3() != bsp_cr3 or x86.interruptsEnabled()) proof.fail("SMP guarded stack final ownership");
    early_console.print("AP guarded trap stack used: helper=");
    const usable_top = cpus[PREPARED_OWNER_CPU].trap_stack_top - TRAP_STACK_TOP_RESERVED;
    numfmt.printDec(usable_top - trap_stack_baseline_low);
    early_console.print(" interrupt=");
    numfmt.printDec(usable_top - trap_stack_interrupt_low);
    early_console.print(" bytes; remaining=");
    numfmt.printDec(trap_stack_interrupt_low - (cpus[PREPARED_OWNER_CPU].trap_stack_top - native_executor.TRAP_STACK_USABLE_BYTES));
    early_console.print(" bytes\n");
    @atomicStore(u32, &trap_stack_phase, TRAP_STACK_DONE, .release);
    proof.pass("SMP_AP_TRAP_STACK");
}

fn verifyGuardedStackGate() void {
    const gate = idt.idt[smp.PREPARED_EXECUTION_IPI_VECTOR];
    const handler = @as(u64, gate.offset_low) | @as(u64, gate.offset_middle) << 16 | @as(u64, gate.offset_high) << 32;
    if (handler != @intFromPtr(&isr116) or gate.selector != gdt.KERNEL_CODE_SEG or gate.ist != 0 or
        gate.type_attr != 0x8e or gate.reserved != 0) proof.fail("SMP guarded stack actual ISR gate");
}

fn verifyGuardedTrapAuthority(index: u8) void {
    const top = cpus[index].trap_stack_top;
    if (x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or top % PAGE_BYTES != 0 or
        native_executor.preparedKernelStackForCpu(index) != top or
        paging.currentPagePermissions(top - native_executor.TRAP_STACK_TOTAL_BYTES) != null)
        proof.fail("SMP guarded stack selected authority");
    var page = top - native_executor.TRAP_STACK_USABLE_BYTES;
    while (page < top) : (page += PAGE_BYTES) {
        var current = paging.getCurrentPageDirectory();
        for ([_]u6{ table.PML4_SHIFT, table.PDPT_SHIFT, table.PAGE_DIRECTORY_SHIFT }) |shift| {
            const entry = current[table.index(page, shift)];
            if (entry & (table.PRESENT | table.WRITABLE | table.USER | table.WRITE_THROUGH | table.CACHE_DISABLE | table.LARGE_PAGE) !=
                table.PRESENT | table.WRITABLE) proof.fail("SMP guarded stack WB supervisor parent");
            const physical = table.address(entry);
            cache_policy.requireAdmittedWriteBack(physical, PAGE_BYTES) catch proof.fail("SMP guarded stack parent cache authority");
            current = @ptrFromInt(paging.mappedRamSpan(physical, PAGE_BYTES) orelse proof.fail("SMP guarded stack parent RAM authority"));
        }
        const leaf = current[table.index(page, table.PAGE_TABLE_SHIFT)];
        if (leaf & (table.PRESENT | table.WRITABLE | table.USER | table.WRITE_THROUGH | table.CACHE_DISABLE | table.LARGE_PAGE | table.NO_EXECUTE) !=
            table.PRESENT | table.WRITABLE | table.NO_EXECUTE) proof.fail("SMP guarded stack WB NX 4K leaf");
        const physical = table.address(leaf);
        cache_policy.requireAdmittedWriteBack(physical, PAGE_BYTES) catch proof.fail("SMP guarded stack leaf cache authority");
        if (paging.mappedRamSpan(physical, PAGE_BYTES) == null) proof.fail("SMP guarded stack backing RAM authority");
    }
}

fn verifyGuardedStackNeighbors() void {
    for (&cpus, 0..) |*cpu, index| {
        const top = cpu.trap_stack_top;
        for ([_]bool{ false, true }) |last| {
            if (trapStackWord(top, last).* != trapStackCanary(@intCast(index), last, true))
                proof.fail("SMP guarded stack end canary");
        }
        // Selected execution may alter only its painted interior. Every word
        // in all fifteen other stacks, and its reserved upper region, survives.
        var cursor = if (index == PREPARED_OWNER_CPU) top - TRAP_STACK_TOP_RESERVED else top - native_executor.TRAP_STACK_USABLE_BYTES + @sizeOf(u64);
        while (cursor < top - @sizeOf(u64)) : (cursor += @sizeOf(u32)) {
            const word: *const volatile u32 = @ptrFromInt(cursor);
            if (word.* != TRAP_PAINT_WORD) proof.fail("SMP guarded stack complete neighbor paint");
        }
    }
}

fn guardedStackLowWater() usize {
    const top = cpus[PREPARED_OWNER_CPU].trap_stack_top;
    var cursor = top - native_executor.TRAP_STACK_USABLE_BYTES + @sizeOf(u64);
    const usable_top = top - TRAP_STACK_TOP_RESERVED;
    while (cursor < usable_top) : (cursor += @sizeOf(u32)) {
        const word: *const volatile u32 = @ptrFromInt(cursor);
        if (word.* != TRAP_PAINT_WORD) return cursor;
    }
    proof.fail("SMP guarded stack missing execution paint");
}

fn guardedStackWindow(index: u8, saved_entry: *const native_entry.State) void {
    const entry_cr4 = x86.readCr4();
    // The real kernel ISR skips state ownership if OSXSAVE or the exact XCR0
    // mask is absent. Prove its standard-state branch before either window;
    // the helper's explicit XRSTOR mask alone cannot establish that branch.
    if (cpu_identity.currentIndex() != index or x86.interruptsEnabled() or
        entry_cr4 & (x86.CR4_OSXSAVE | x86.CR4_FRED) != x86.CR4_OSXSAVE or
        x86.readXcr0() != xstate.enabled_mask or gsEntryModes() != 0) reject(index);
    const cpu = &cpus[index];
    model.initialize(&cpu.seed, index % 3);
    model.initializeCanary(&cpu.restored);
    var restored_flags: usize = 0;
    const gp_match = zigos_arch_smp_poll_trap_stack(&cpu.seed, &cpu.restored, &restored_flags, cpu.trap_stack_top);
    const observed = native_entry.current().*;
    if (gp_match != 1 or restored_flags & (FLAG_DF | FLAG_AC) != FLAG_DF | FLAG_AC or
        !verifyRestoredState(&cpu.seed, &cpu.restored) or x86.interruptsEnabled() or interrupt_context.active() or
        x86.readCr4() != entry_cr4 or x86.readXcr0() != xstate.enabled_mask or
        !paging.kernelAddressSpaceActive() or x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3 or
        !std.mem.eql(u8, std.mem.asBytes(&observed), std.mem.asBytes(saved_entry))) reject(index);
}

fn guardedStackAfterReturn(_: *anyopaque, ran: bool) void {
    // All source/issuer/task/root accesses ended at ACK. This hook reads only
    // permanent phase state and the copied ran bit before static completion.
    trap_stack_owner_ran = ran;
    @atomicStore(u32, &trap_stack_returned, 1, .release);
    waitForTransportWord(&trap_stack_released, 1);
}

fn holdGuardedTrapStack(index: u8) void {
    if (x86.interruptsEnabled() or cpu_identity.currentIndex() != index or !paging.kernelAddressSpaceActive()) reject(index);
    @atomicStore(u8, &trap_stack_quiescent[index], 1, .release);
    if (index != PREPARED_OWNER_CPU) {
        waitForTransportWord(&trap_stack_phase, TRAP_STACK_DONE);
        return;
    }
    const saved_entry = native_entry.current().*;
    const assigned_top = native_executor.preparedKernelStackForCpu(index) orelse reject(index);
    if (assigned_top != cpus[index].trap_stack_top or saved_entry.native_entry_modes != 0) reject(index);
    waitForTransportWord(&trap_stack_phase, 1);
    verifyGuardedStackGate();
    verifyGuardedTrapAuthority(index);
    // Drain old harmless hints before the no-IPI baseline. No fake prompt is
    // written by this proof, and the pending command must remain unclaimed.
    _ = dispatch_transport.global.takePrompt(index) catch reject(index);
    guardedStackWindow(index, &saved_entry);
    trap_stack_baseline_low = guardedStackLowWater();
    rejectPromptedEmpty(index, &saved_entry);
    @atomicStore(u32, &trap_stack_checked, 1, .release);
    waitForTransportWord(&trap_stack_phase, 2);
    guardedStackWindow(index, &saved_entry);
    trap_stack_interrupt_low = guardedStackLowWater();
    if (trap_stack_interrupt_low >= trap_stack_baseline_low or
        trap_stack_baseline_low - trap_stack_interrupt_low < xstate.image_bytes) reject(index);
    @atomicStore(u32, &trap_stack_checked, 2, .release);
    // The BSP restores the complete shared IDT entry after this CLI witness.
    waitForTransportWord(&trap_stack_phase, 3);
    _ = native_entry.initializeCpu(index, assigned_top);
    if (!native_executor.runPromptedPreparedExecutionForArchitectureProof(
        preparedOwnerCallback,
        &prepared_owner_expectation,
        &saved_entry,
        null,
        guardedStackAfterReturn,
        &trap_stack_returned,
    )) reject(index);
    // The actual runner consumed the real ISR prompt only after IRET. All
    // domain accesses ended at ACK before static completion and this receipt.
    @atomicStore(u32, &trap_stack_completed, 1, .release);
    waitForTransportWord(&trap_stack_phase, TRAP_STACK_DONE);
}

fn proveBrokerReceives(
    runtime: *task_runtime.Runtime,
    kernel: *native_kernel.Kernel,
    port: *const component_port.KernelPort,
    anchor: *native_executor.Executor,
    receiver: *task_runtime.TaskRecord,
    receiving: *const [PROOF_CPU_COUNT - 1]u64,
    anchor_space: *const paging.UserAddressSpace,
    admitted_frames: usize,
) capability.Capability {
    const caps = kernel.capability_table;
    const endpoints = kernel.endpoint_table;
    // One shared original proves copies retain sender authority. Unique moved
    // gifts are attached and enqueued one at a time, respecting the actual
    // 24-entry task attachment ceiling without changing global capacity.
    const copy_gift = mintBrokerGift(kernel, receiver, 0x6100);
    const original_copy = copy_gift;
    for (0..2) |round| {
        const moved = round == 1;
        const receipt_phase: u32 = @intCast(round + 1);
        const request_phase = if (moved) BROKER_RECV_MOVE_REQUEST else BROKER_RECV_COPY_REQUEST;
        const reply_phase = if (moved) BROKER_RECV_MOVE_REPLY else BROKER_RECV_COPY_REPLY;
        var gifts: [PROOF_CPU_COUNT - 1]u64 = undefined;
        for (&private_roots, dispatch_task_ids, 0..) |*space, task_id, index| {
            const cpu: u8 = @intCast(index + 1);
            const task = runtime.findConst(task_id) orelse proof.fail("SMP broker receive caller");
            if (task.state != .active or task.capability_count != 2 + round or receiver.capability_count != private_roots.len + 1)
                proof.fail("SMP broker receive initial attachments");
            const gift = if (moved) mintBrokerGift(kernel, receiver, 0x6200 + @as(u64, cpu)) else copy_gift;
            gifts[index] = gift.id;
            const channel = caps.query(task.capabilityIds()[1]) orelse proof.fail("SMP broker receive channel");
            const payload = brokerReceivePayload(cpu, receipt_phase);
            kernel.endpointSend(.{ .caller_task_id = receiver.id, .presented_capability_id = receiving[index], .target = .none }, brokerReceiveCorrelation(cpu, receipt_phase), &payload, 0, gift.id, moved, 55 + round) catch
                proof.fail("SMP broker receive queue publication");
            const queued = endpoints.descriptor(object_ids.endpoint(channel.target.id)) catch proof.fail("SMP broker queued receive descriptor");
            if (queued.queued_messages != 1 or !endpoints.hasPendingForTask(object_ids.task(task.id)) or
                caps.query(gift.id) == null or receiver.capability_count != private_roots.len + 1 or
                taskHasCapability(receiver, gift.id) == moved)
                proof.fail("SMP broker receive queued ownership");
            initializeBrokerOutputs(space, cpu, receipt_phase);
            const wire = abi.EndpointRecvWireRequest{
                .header = component_port.makeHeader(.endpoint_recv, task.id),
                .endpoint_capability_id = channel.id,
                .receiver_task_id = task.id,
                .payload_address = BROKER_PAYLOAD,
                .payload_capacity = abi.ENDPOINT_INLINE_BYTES,
                .attached_capability_address = BROKER_CAPABILITY,
            };
            paging.writeOwnedUserRange(space, BROKER_RECV_REQUEST, std.mem.asBytes(&wire)) catch proof.fail("SMP broker receive wire staging");
        }
        const before_receive = caps.activeCount();
        const expected_before: usize = if (moved) 5 * private_roots.len + 1 else 3 * private_roots.len + 1;
        if (before_receive != expected_before) proof.fail("SMP broker queued gift accounting");
        const request_count = @atomicLoad(u32, &broker_request_count, .acquire);
        @atomicStore(u32, &broker_phase, request_phase, .release);
        for (dispatch_tickets) |ticket| if (!smp.notifySyscallCompletion(ticket.cpu)) proof.fail("SMP broker receive request wake");
        const deadline = tsc_clock.afterMilliseconds(2000);
        while (@atomicLoad(u32, &broker_request_count, .acquire) == request_count) {
            if (deadline.expired()) proof.fail("SMP broker receive request interrupt timeout");
            brokerWait(0, null);
        }
        waitForBrokerReceive(receipt_phase, false);
        if (!event_wake.take().scheduler) proof.fail("SMP broker receive BSP wake latch");
        for (dispatch_tickets, 0..) |ticket, index| {
            const task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP broker receive retained task");
            const original = caps.query(gifts[index]) orelse proof.fail("SMP broker receive original gift");
            const task_generation = task.capabilityGeneration();
            if (!brokerOutputsAreCanary(&private_roots[index], ticket.cpu, receipt_phase) or
                !brokerOutputsAreCanary(anchor_space, 0, 0)) proof.fail("SMP broker receive output canaries");
            var claim: dispatch_ownership.ClaimedSyscall = undefined;
            runtime.execution.claimSyscallInto(ticket.cpu, &claim) catch proof.fail("SMP broker receive claim");
            if (claim.envelope.opcode != abi.opcode(.endpoint_recv) or claim.envelope.response_addr != BROKER_RESPONSE or
                claim.envelope.response_len != @sizeOf(abi.EndpointRecvResponse)) proof.fail("SMP broker receive envelope");
            var copy: syscall_broker.CopySession = undefined;
            if (!anchor.prepareSyscallCopySession(&claim, &copy)) proof.fail("SMP broker receive production session");
            syscall_broker.serviceClaim(port, &claim, &copy, 60 + round) catch proof.fail("SMP broker receive service");
            var observed: abi.CapabilityDescriptor = undefined;
            paging.readOwnedUserRange(&private_roots[index], BROKER_CAPABILITY, std.mem.asBytes(&observed)) catch proof.fail("SMP broker receive capability readback");
            const passed = caps.query(observed.capability_id) orelse proof.fail("SMP broker received gift absent");
            const channel = caps.query(task.capabilityIds()[1]) orelse proof.fail("SMP broker receive recipient channel");
            const sending = caps.query(receiving[index]) orelse proof.fail("SMP broker receive sender channel");
            if (passed.id == original.id or !passed.holder.eql(task.owner) or !passed.issuer.eql(original.issuer) or
                !std.meta.eql(passed.target, original.target) or passed.rights.toBits() != original.rights.toBits() or
                passed.scope.task_id != task.id or !passed.scope.local_only or passed.lease.expires_at_ticks != 1000 or
                task.capability_count != 3 + round or task.capabilityGeneration() == task_generation or
                !taskHasCapability(task, passed.id) or taskHasCapability(task, original.id) or
                (caps.query(original.id) == null) != moved)
                proof.fail("SMP broker received grant transfer");
            broker_expected_receipts[round][index] = .{
                .capability = brokerCapabilityDescriptor(&passed),
                .response = .{
                    .present = 1,
                    .has_attached_capability = 1,
                    ._reserved = @splat(0),
                    .message = .{
                        .endpoint_id = channel.target.id,
                        .sender_endpoint_id = sending.target.id,
                        .sender_task_id = receiver.id,
                        .correlation_id = brokerReceiveCorrelation(ticket.cpu, receipt_phase),
                        .attached_capability_id = original.id,
                        .payload_len = abi.ENDPOINT_INLINE_BYTES,
                        .flags = @bitCast(endpoint.EndpointFlags{ .local_only = true, .carries_capability = true }),
                    },
                },
            };
            const queued = endpoints.descriptor(object_ids.endpoint(channel.target.id)) catch proof.fail("SMP broker consumed receive descriptor");
            const expected_count = before_receive + if (moved) @as(usize, 0) else index + 1;
            if (!verifyBrokerReceiveOutputs(&private_roots[index], &broker_expected_receipts[round][index], ticket.cpu, receipt_phase) or
                !brokerOutputsAreCanary(anchor_space, 0, 0) or queued.queued_messages != 0 or
                endpoints.hasPendingForTask(object_ids.task(task.id)) or caps.activeCount() != expected_count or
                task.state != .active or runtime.findAddressSpaceConst(task.address_space_id) == null or
                runtime.execution.syscallIdle(ticket) or paging.frameStats().allocated != admitted_frames)
                proof.fail("SMP broker receive once-only outputs");
            const mutation = caps.mutationGeneration();
            const attached_generation = task.capabilityGeneration();
            if (syscall_broker.serviceClaim(port, &claim, &copy, 70)) |_| proof.fail("SMP broker duplicate receive service") else |_| {}
            if (caps.mutationGeneration() != mutation or task.capabilityGeneration() != attached_generation or
                task.capability_count != 3 + round or caps.activeCount() != expected_count or
                (endpoints.descriptor(object_ids.endpoint(channel.target.id)) catch proof.fail("SMP broker duplicate receive descriptor")).queued_messages != 0 or
                !verifyBrokerReceiveOutputs(&private_roots[index], &broker_expected_receipts[round][index], ticket.cpu, receipt_phase))
                proof.fail("SMP broker duplicate receive mutation");
            if (runtime.collectExecution(ticket)) |_| proof.fail("SMP broker receive premature collection") else |_| {}
        }
        const retained_copy = caps.query(copy_gift.id) orelse proof.fail("SMP broker copy source retired");
        if (!std.meta.eql(retained_copy, original_copy) or !taskHasCapability(receiver, copy_gift.id) or
            receiver.capability_count != private_roots.len + 1 or
            caps.activeCount() != (if (moved) 5 * private_roots.len + 1 else 4 * private_roots.len + 1))
            proof.fail("SMP broker retained copy accounting");
        @atomicStore(u32, &broker_phase, reply_phase, .release);
        for (dispatch_tickets) |ticket| if (!smp.notifySyscallCompletion(ticket.cpu)) proof.fail("SMP broker receive reply wake");
        waitForBrokerReceive(receipt_phase, true);
    }
    return original_copy;
}

fn proveBrokerCloses(
    runtime: *task_runtime.Runtime,
    kernel: *native_kernel.Kernel,
    port: *const component_port.KernelPort,
    anchor: *native_executor.Executor,
    receiver: *task_runtime.TaskRecord,
    receiving: *const [PROOF_CPU_COUNT - 1]u64,
    anchor_space: *const paging.UserAddressSpace,
    copy_gift: *const capability.Capability,
    admitted_frames: usize,
) void {
    const caps = kernel.capability_table;
    const endpoints = kernel.endpoint_table;
    var channels: [PROOF_CPU_COUNT - 1]capability.Capability = undefined;
    var queued_moves: [PROOF_CPU_COUNT - 1]u64 = undefined;
    if (caps.activeCount() != 5 * private_roots.len + 1 or endpoints.activeCount() != 2 * private_roots.len or
        receiver.capability_count != private_roots.len + 1 or kernel.endpoint_wake_sink != null)
        proof.fail("SMP broker close initial ownership");
    // Copies retain this original; moves remain globally live but unattached
    // until the actual close drains them. Mint and enqueue one at a time to
    // preserve the existing per-task attachment ceiling.
    for (&private_roots, dispatch_task_ids, 0..) |*space, task_id, index| {
        const task = runtime.findConst(task_id) orelse proof.fail("SMP broker close caller");
        const cpu: u8 = @intCast(index + 1);
        if (task.state != .active or task.capability_count != 4) proof.fail("SMP broker close caller attachments");
        const channel = caps.query(task.capabilityIds()[1]) orelse proof.fail("SMP broker close channel authority");
        channels[index] = channel;
        const moved = mintBrokerGift(kernel, receiver, 0x6300 + @as(u64, cpu));
        queued_moves[index] = moved.id;
        const payload = brokerReceivePayload(cpu, 3);
        kernel.endpointSend(.{ .caller_task_id = receiver.id, .presented_capability_id = receiving[index], .target = .none }, brokerReceiveCorrelation(cpu, 3), &payload, 0, copy_gift.id, false, 75) catch
            proof.fail("SMP broker close queued copy");
        kernel.endpointSend(.{ .caller_task_id = receiver.id, .presented_capability_id = receiving[index], .target = .none }, brokerReceiveCorrelation(cpu, 4), &payload, 0, moved.id, true, 76) catch
            proof.fail("SMP broker close queued move");
        const queued = endpoints.descriptor(object_ids.endpoint(channel.target.id)) catch proof.fail("SMP broker close queued descriptor");
        if (queued.queued_messages != 2 or !endpoints.hasPendingForTask(object_ids.task(task.id)) or
            caps.query(moved.id) == null or taskHasCapability(receiver, moved.id) or
            !taskHasCapability(receiver, copy_gift.id) or receiver.capability_count != private_roots.len + 1)
            proof.fail("SMP broker close queue ownership");
        initializeBrokerOutputs(space, cpu, 3);
        const request = abi.EndpointCloseWireRequest{
            .header = component_port.makeHeader(.endpoint_close, task.id),
            .endpoint_capability_id = channel.id,
        };
        paging.writeOwnedUserRange(space, BROKER_RECV_REQUEST, std.mem.asBytes(&request)) catch proof.fail("SMP broker close request staging");
    }
    if (caps.activeCount() != 6 * private_roots.len + 1 or endpoints.hasPendingForTask(object_ids.task(receiver.id)))
        proof.fail("SMP broker close queued grant accounting");
    const Wake = struct {
        receiver: u64,
        count: usize = 0,
        fn notify(context: *anyopaque, task_id: u64, now_ticks: u64) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or
                task_id != self.receiver or now_ticks != 80) proof.fail("SMP broker close peer wake");
            self.count += 1;
        }
    };
    var wake = Wake{ .receiver = receiver.id };
    // Publication/close callbacks are BSP-owned and synchronous. This scoped
    // observer is installed only after enqueue wakes have already completed.
    kernel.bindEndpointWakeSink(.{ .context = &wake, .wake = Wake.notify });
    const request_count = @atomicLoad(u32, &broker_request_count, .acquire);
    @atomicStore(u32, &broker_phase, BROKER_CLOSE_REQUEST, .release);
    for (dispatch_tickets) |ticket| if (!smp.notifySyscallCompletion(ticket.cpu)) proof.fail("SMP broker close request wake");
    const deadline = tsc_clock.afterMilliseconds(2000);
    while (@atomicLoad(u32, &broker_request_count, .acquire) == request_count) {
        if (deadline.expired()) proof.fail("SMP broker close request interrupt timeout");
        brokerWait(0, null);
    }
    waitForBroker(.close_published);
    if (!event_wake.take().scheduler) proof.fail("SMP broker close BSP wake latch");
    for (dispatch_tickets, 0..) |ticket, index| {
        const task = runtime.findConst(dispatch_task_ids[index]) orelse proof.fail("SMP broker close retained task");
        const channel = channels[index];
        const peer_before = caps.query(receiving[index]) orelse proof.fail("SMP broker close peer authority");
        const retained = [_]capability.Capability{
            caps.query(task.capabilityIds()[0]) orelse proof.fail("SMP broker close termination authority"),
            caps.query(task.capabilityIds()[2]) orelse proof.fail("SMP broker close received copy authority"),
            caps.query(task.capabilityIds()[3]) orelse proof.fail("SMP broker close received move authority"),
        };
        const generation = task.capabilityGeneration();
        var claim: dispatch_ownership.ClaimedSyscall = undefined;
        runtime.execution.claimSyscallInto(ticket.cpu, &claim) catch proof.fail("SMP broker close claim");
        if (claim.envelope.opcode != abi.opcode(.endpoint_close) or
            claim.envelope.response_addr != std.math.maxInt(usize) or claim.envelope.response_len != std.math.maxInt(usize))
            proof.fail("SMP broker close status-only envelope");
        var copy: syscall_broker.CopySession = undefined;
        if (!anchor.prepareSyscallCopySession(&claim, &copy)) proof.fail("SMP broker close production session");
        syscall_broker.serviceClaim(port, &claim, &copy, 80) catch proof.fail("SMP broker close service");
        if (endpoints.descriptor(object_ids.endpoint(channel.target.id))) |_| proof.fail("SMP broker closed endpoint retained") else |err| {
            if (err != error.EndpointNotFound) proof.fail("SMP broker close descriptor result");
        }
        const peer = endpoints.descriptor(object_ids.endpoint(peer_before.target.id)) catch proof.fail("SMP broker close retained peer");
        const peer_slot = endpoints.arena.getConstByHandle(.{ .value = peer.endpoint_id }) orelse proof.fail("SMP broker close peer slot");
        if (caps.query(channel.id) != null or caps.query(queued_moves[index]) != null or
            taskHasCapability(task, channel.id) or task.capability_count != 3 or task.capabilityGeneration() == generation or
            peer.peer_endpoint_id != 0 or peer.queued_messages != 0 or !peer_slot.endpoint.peer_closed or
            endpoints.hasPendingForTask(object_ids.task(task.id)) or endpoints.hasPendingForTask(object_ids.task(receiver.id)) or
            endpoints.activeCount() != 2 * private_roots.len - index - 1 or
            caps.activeCount() != 6 * private_roots.len + 1 - 2 * (index + 1) or wake.count != index + 1 or
            task.state != .active or task.execution_component_count != 1 or runtime.findAddressSpaceConst(task.address_space_id) == null or
            (runtime.execution.phase(ticket) catch proof.fail("SMP broker close retained lease")) != .running or
            runtime.execution.syscallIdle(ticket) or runtime.execution.stopRequested(ticket) or
            paging.frameStats().allocated != admitted_frames or !brokerOutputsAreCanary(&private_roots[index], ticket.cpu, 3) or
            !brokerOutputsAreCanary(anchor_space, 0, 0)) proof.fail("SMP broker close exact retirement");
        for (retained) |owned| {
            const after = caps.query(owned.id) orelse proof.fail("SMP broker close unrelated grant retired");
            if (!std.meta.eql(after, owned) or !taskHasCapability(task, owned.id)) proof.fail("SMP broker close unrelated grant changed");
        }
        const peer_after = caps.query(peer_before.id) orelse proof.fail("SMP broker close peer grant retired");
        const copied = caps.query(copy_gift.id) orelse proof.fail("SMP broker close copied grant retired");
        if (!std.meta.eql(peer_after, peer_before) or !std.meta.eql(copied, copy_gift.*) or
            !taskHasCapability(receiver, copy_gift.id) or receiver.capability_count != private_roots.len + 1)
            proof.fail("SMP broker close retained peer and copy authority");
        var peer_payload: [abi.ENDPOINT_INLINE_BYTES]u8 = @splat(0xcc);
        if (kernel.endpointRecv(.{ .caller_task_id = receiver.id, .presented_capability_id = receiving[index], .target = .none }, receiver.id, &peer_payload, 81)) |_| proof.fail("SMP broker closed peer receive admitted") else |err| {
            if (err != error.PeerClosed) proof.fail("SMP broker close peer receive result");
        }
        if (!std.mem.allEqual(u8, &peer_payload, 0xcc)) proof.fail("SMP broker closed peer receive output");
        const mutation = caps.mutationGeneration();
        const attachments = task.capabilityGeneration();
        if (syscall_broker.serviceClaim(port, &claim, &copy, 82)) |_| proof.fail("SMP broker duplicate close service") else |err| {
            if (err != error.WrongPhase) proof.fail("SMP broker duplicate close result");
        }
        if (caps.mutationGeneration() != mutation or task.capabilityGeneration() != attachments or
            caps.activeCount() != 6 * private_roots.len + 1 - 2 * (index + 1) or
            endpoints.activeCount() != 2 * private_roots.len - index - 1 or wake.count != index + 1 or
            !brokerOutputsAreCanary(&private_roots[index], ticket.cpu, 3)) proof.fail("SMP broker duplicate close mutation");
        if (runtime.collectExecution(ticket)) |_| proof.fail("SMP broker close premature collection") else |_| {}
        for (index + 1..private_roots.len) |neighbor| {
            const pending = runtime.findConst(dispatch_task_ids[neighbor]) orelse proof.fail("SMP broker close neighbor");
            if (pending.state != .active or pending.capability_count != 4 or caps.query(channels[neighbor].id) == null or
                caps.query(queued_moves[neighbor]) == null or
                (endpoints.descriptor(object_ids.endpoint(channels[neighbor].target.id)) catch proof.fail("SMP broker close neighbor endpoint")).queued_messages != 2 or
                !endpoints.hasPendingForTask(object_ids.task(pending.id)) or
                runtime.findAddressSpaceConst(pending.address_space_id) == null or !runtime.execution.hasLeaseForTask(pending.id) or
                !brokerOutputsAreCanary(&private_roots[neighbor], @intCast(neighbor + 1), 3))
                proof.fail("SMP broker close neighbor ownership");
        }
    }
    kernel.clearEndpointWakeSink();
    if (wake.count != private_roots.len or caps.activeCount() != 4 * private_roots.len + 1)
        proof.fail("SMP broker close final accounting");
    @atomicStore(u32, &broker_phase, BROKER_CLOSE_REPLY, .release);
    for (dispatch_tickets) |ticket| if (!smp.notifySyscallCompletion(ticket.cpu)) proof.fail("SMP broker close reply wake");
    waitForBroker(.close_consumed);
}

fn mintBrokerGift(kernel: *native_kernel.Kernel, owner: *task_runtime.TaskRecord, target: u64) capability.Capability {
    const gift = kernel.capability_table.mintBootRoot(.{
        .holder = owner.owner,
        .issuer = kernel.policy_authority,
        .target = .{ .kind = .service, .id = target },
        .rights = .{ .service = .{ .time_query = true, .capability_pass = true } },
        .scope = .{ .task_id = owner.id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1000 },
    }) catch proof.fail("SMP broker gift authority");
    kernel.runtime.grantCapability(owner.id, gift.id) catch proof.fail("SMP broker gift attachment");
    return gift;
}

fn taskHasCapability(task: *const task_runtime.TaskRecord, id: u64) bool {
    for (task.capabilityIds()) |attached| if (attached == id) return true;
    return false;
}

fn brokerCapabilityDescriptor(owned: *const capability.Capability) abi.CapabilityDescriptor {
    return .{
        .capability_id = owned.id,
        .target_id = owned.target.id,
        .rights = owned.rights.toBits(),
        .revocation_generation = owned.revocation_generation,
        .expires_at_ticks = owned.lease.expires_at_ticks,
        .scope_task_id = owned.scope.task_id orelse 0,
        .scope_workspace_id = owned.scope.workspace_id orelse 0,
        .scope_flags = @bitCast(abi.ScopeFlags{
            .local_only = owned.scope.local_only,
            .broker_only = owned.scope.broker_only,
            .task_scoped = owned.scope.task_id != null,
            .workspace_scoped = owned.scope.workspace_id != null,
            .ephemeral = !owned.lease.renewable,
        }),
    };
}

fn brokerReceiveCorrelation(cpu: u8, round: u32) u64 {
    return @as(u64, round) << 32 | cpu;
}

fn brokerReceivePayload(cpu: u8, round: u32) [abi.ENDPOINT_INLINE_BYTES]u8 {
    var payload = brokerPayload(cpu);
    for (&payload) |*byte| byte.* ^= @as(u8, @intCast(round)) * 0x31;
    return payload;
}

fn brokerOutputCanary(cpu: u8, round: u32) u8 {
    return if (cpu == 0) 0xb5 else 0xa0 ^ cpu ^ @as(u8, @intCast(round));
}

fn initializeBrokerOutputs(space: *const paging.UserAddressSpace, cpu: u8, round: u32) void {
    const canary: [abi.ENDPOINT_INLINE_BYTES]u8 = @splat(brokerOutputCanary(cpu, round));
    paging.writeOwnedUserRange(space, BROKER_PAYLOAD, &canary) catch proof.fail("SMP broker payload output canary");
    paging.writeOwnedUserRange(space, BROKER_CAPABILITY, canary[0..@sizeOf(abi.CapabilityDescriptor)]) catch proof.fail("SMP broker capability output canary");
    paging.writeOwnedUserRange(space, BROKER_RESPONSE, canary[0..@sizeOf(abi.EndpointRecvResponse)]) catch proof.fail("SMP broker response output canary");
}

fn brokerOutputsAreCanary(space: *const paging.UserAddressSpace, cpu: u8, round: u32) bool {
    var bytes: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    inline for (.{ .{ BROKER_PAYLOAD, abi.ENDPOINT_INLINE_BYTES }, .{ BROKER_CAPABILITY, @sizeOf(abi.CapabilityDescriptor) }, .{ BROKER_RESPONSE, @sizeOf(abi.EndpointRecvResponse) } }) |span| {
        paging.readOwnedUserRange(space, span[0], bytes[0..span[1]]) catch return false;
        for (bytes[0..span[1]]) |byte| if (byte != brokerOutputCanary(cpu, round)) return false;
    }
    return true;
}

fn verifyBrokerReceiveOutputs(space: *const paging.UserAddressSpace, receipt: *const BrokerReceipt, cpu: u8, round: u32) bool {
    var response: abi.EndpointRecvResponse = undefined;
    var attached: abi.CapabilityDescriptor = undefined;
    var payload: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    paging.readOwnedUserRange(space, BROKER_RESPONSE, std.mem.asBytes(&response)) catch return false;
    paging.readOwnedUserRange(space, BROKER_CAPABILITY, std.mem.asBytes(&attached)) catch return false;
    paging.readOwnedUserRange(space, BROKER_PAYLOAD, &payload) catch return false;
    const expected_payload = brokerReceivePayload(cpu, round);
    return std.mem.eql(u8, std.mem.asBytes(&response), std.mem.asBytes(&receipt.response)) and
        std.mem.eql(u8, std.mem.asBytes(&attached), std.mem.asBytes(&receipt.capability)) and
        std.mem.eql(u8, &payload, &expected_payload) and
        response.message._reserved == 0 and attached._reserved_generation == 0 and attached._reserved_tail == 0;
}

fn waitForBrokerReceive(phase: u32, consumed: bool) void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    for (cpus[1..]) |*cpu| {
        const target = if (consumed) &cpu.broker_recv_consumed else &cpu.broker_recv_published;
        while (@atomicLoad(u32, target, .acquire) != phase) {
            if (deadline.expired() or @atomicLoad(u8, &cpu.status, .acquire) != 1) proof.fail("SMP broker receive owner timeout");
            asm volatile ("pause");
        }
    }
}

fn prepareBrokerAddressRecord(runtime: *task_runtime.Runtime, task: *const task_runtime.TaskRecord) void {
    const record = runtime.findAddressSpace(task.address_space_id) orelse proof.fail("SMP broker address metadata");
    if (record.owner_task_id != task.id or record.region_count != 0) proof.fail("SMP broker address metadata owner");
    record.regions[0] = .{
        .kind = .load_segment,
        .virtual_address = BROKER_PAGE,
        .size_bytes = BROKER_PRIVATE_BYTES,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true, .write = true },
    };
    record.region_count = 1;
}

fn brokerPayload(cpu: u8) [abi.ENDPOINT_INLINE_BYTES]u8 {
    var bytes: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = cpu ^ @as(u8, @truncate(index * 3));
    return bytes;
}

fn waitForBroker(comptime field: enum { published, consumed, ipc_published, ipc_consumed, close_published, close_consumed }) void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    for (cpus[1..]) |*cpu| {
        const target = switch (field) {
            .published => &cpu.broker_published,
            .consumed => &cpu.broker_consumed,
            .ipc_published => &cpu.broker_ipc_published,
            .ipc_consumed => &cpu.broker_ipc_consumed,
            .close_published => &cpu.broker_close_published,
            .close_consumed => &cpu.broker_close_consumed,
        };
        while (@atomicLoad(u8, target, .acquire) != 1) {
            if (deadline.expired() or @atomicLoad(u8, &cpu.status, .acquire) != 1) proof.fail("SMP broker owner progress timeout");
            asm volatile ("pause");
        }
    }
}

fn waitForBrokerTlb() void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    for (cpus[1..]) |*cpu| {
        while (@atomicLoad(u32, &cpu.broker_tlb_count, .acquire) != 1) {
            if (deadline.expired() or @atomicLoad(u8, &cpu.status, .acquire) != 1) proof.fail("SMP broker parked TLB timeout");
            asm volatile ("pause");
        }
    }
}

fn brokerWait(index: u8, expected: ?*const native_entry.State) void {
    const cpu = &cpus[index];
    model.initialize(&cpu.seed, index % 3);
    model.initializeCanary(&cpu.restored);
    var restored_flags: usize = 0;
    const gp_match = if (index == 0)
        zigos_arch_smp_poll_for_ipi(&cpu.seed, &cpu.restored, &restored_flags)
    else
        zigos_arch_smp_wait_for_ipi(&cpu.seed, &cpu.restored, &restored_flags);
    if (gp_match != 1 or restored_flags & (FLAG_DF | FLAG_AC) != FLAG_DF | FLAG_AC or
        !verifyRestoredState(&cpu.seed, &cpu.restored) or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or
        x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3) reject(index);
    if (expected) |snapshot| {
        const observed = native_entry.current().*;
        if (!std.mem.eql(u8, std.mem.asBytes(&observed), std.mem.asBytes(snapshot))) reject(index);
    } else if (!verifyCurrentGs(index, true)) reject(index);
}

fn holdBrokerRequest(index: u8) void {
    while (@atomicLoad(u32, &broker_phase, .acquire) != 1) asm volatile ("pause");
    const runtime = dispatch_runtime orelse reject(index);
    const ticket = dispatch_tickets[index - 1];
    var bound: dispatch_ownership.BoundIdentity = undefined;
    runtime.execution.startInto(ticket, &bound) catch reject(index);
    const space = &private_roots[index - 1];
    if (bound.mapping_handle != broker_mapping_handles[index].value or bound.physical_root != space.switch_cr3 & x86.CR3_ADDRESS_MASK or
        bound.identity.task_id != dispatch_task_ids[index - 1] or bound.identity.address_space_id != dispatch_address_ids[index - 1])
        reject(index);
    paging.switchToUserAddressSpace(space);
    if (paging.kernelAddressSpaceActive() or paging.getCurrentPageDirectory() != space.directory) reject(index);
    paging.switchToKernelAddressSpace();
    if (!paging.kernelAddressSpaceActive() or x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3 or x86.interruptsEnabled()) reject(index);
    const entry = native_entry.current();
    entry.active_task_id = bound.identity.task_id;
    entry.userspace_xstate = @intFromPtr(&cpus[index].seed);
    entry.kernel_xstate = @intFromPtr(&cpus[index].restored);
    entry.resume_rsp = cpus[index].stack_top - x86.FRED_STACK_ALIGNMENT;
    entry.resume_rip = @intFromPtr(&apEntry);
    entry.resume_requested = 0;
    const snapshot = entry.*;
    var key: dispatch_ownership.RequestKey = undefined;
    runtime.execution.submitSyscallInto(ticket, .{
        .opcode = abi.opcode(.endpoint_send),
        .request_addr = BROKER_SEND_REQUEST,
        .response_addr = std.math.maxInt(usize),
        .response_len = std.math.maxInt(usize),
    }, &key) catch reject(index);
    if (runtime.execution.acknowledgeOwnedRootReturn(ticket)) |_| reject(index) else |err| {
        if (err != error.SyscallInFlight) reject(index);
    }
    @atomicStore(u8, &cpus[index].broker_ipc_published, 1, .release);
    if (!smp.notifySyscallRequest()) reject(index);
    while (@atomicLoad(u32, &broker_phase, .acquire) != 2 or
        @atomicLoad(u32, &cpus[index].broker_completion_count, .acquire) == 0) brokerWait(index, &snapshot);
    var reply: dispatch_ownership.Reply = undefined;
    runtime.execution.consumeSyscallInto(key, &reply) catch reject(index);
    if (reply.status != @backingInt(abi.SyscallStatus.success) or reply.denial_reason != @backingInt(abi.DenialReason.none) or
        reply.bytes_written != 0 or !runtime.execution.syscallIdle(ticket) or runtime.execution.stopRequested(ticket) or
        @atomicLoad(u32, &cpus[index].broker_stop_count, .acquire) != 0 or
        @atomicLoad(u32, &cpus[index].broker_tlb_count, .acquire) != 1) reject(index);
    @atomicStore(u8, &cpus[index].broker_ipc_consumed, 1, .release);
    for (0..2) |round| {
        const receipt_phase: u32 = @intCast(round + 1);
        const request_phase = if (round == 0) BROKER_RECV_COPY_REQUEST else BROKER_RECV_MOVE_REQUEST;
        const reply_phase = if (round == 0) BROKER_RECV_COPY_REPLY else BROKER_RECV_MOVE_REPLY;
        while (@atomicLoad(u32, &broker_phase, .acquire) != request_phase) brokerWait(index, &snapshot);
        const previous_receive_sequence = key.sequence;
        const receive_completions = @atomicLoad(u32, &cpus[index].broker_completion_count, .acquire);
        runtime.execution.submitSyscallInto(ticket, .{
            .opcode = abi.opcode(.endpoint_recv),
            .request_addr = BROKER_RECV_REQUEST,
            .response_addr = BROKER_RESPONSE,
            .response_len = @sizeOf(abi.EndpointRecvResponse),
        }, &key) catch reject(index);
        if (key.sequence <= previous_receive_sequence) reject(index);
        if (runtime.execution.acknowledgeOwnedRootReturn(ticket)) |_| reject(index) else |err| {
            if (err != error.SyscallInFlight) reject(index);
        }
        @atomicStore(u32, &cpus[index].broker_recv_published, receipt_phase, .release);
        if (!smp.notifySyscallRequest()) reject(index);
        while (@atomicLoad(u32, &broker_phase, .acquire) != reply_phase or
            @atomicLoad(u32, &cpus[index].broker_completion_count, .acquire) <= receive_completions) brokerWait(index, &snapshot);
        runtime.execution.consumeSyscallInto(key, &reply) catch reject(index);
        var retained: dispatch_ownership.BoundIdentity = undefined;
        runtime.execution.boundIdentityInto(ticket, &retained) catch reject(index);
        if (reply.status != @backingInt(abi.SyscallStatus.success) or reply.denial_reason != @backingInt(abi.DenialReason.none) or
            reply.bytes_written != @sizeOf(abi.EndpointRecvResponse) or !runtime.execution.syscallIdle(ticket) or
            runtime.execution.stopRequested(ticket) or !std.meta.eql(retained, bound) or
            !paging.kernelAddressSpaceActive() or x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3 or
            !verifyBrokerReceiveOutputs(space, &broker_expected_receipts[round][index - 1], index, receipt_phase) or
            @atomicLoad(u32, &cpus[index].broker_stop_count, .acquire) != 0 or
            @atomicLoad(u32, &cpus[index].broker_tlb_count, .acquire) != 1) reject(index);
        // User output is inspected while the exact lease and private root are
        // still owned. This publication is not an execution return ACK.
        @atomicStore(u32, &cpus[index].broker_recv_consumed, receipt_phase, .release);
    }
    while (@atomicLoad(u32, &broker_phase, .acquire) != BROKER_CLOSE_REQUEST) brokerWait(index, &snapshot);
    const previous_close_sequence = key.sequence;
    const close_completions = @atomicLoad(u32, &cpus[index].broker_completion_count, .acquire);
    runtime.execution.submitSyscallInto(ticket, .{
        .opcode = abi.opcode(.endpoint_close),
        .request_addr = BROKER_RECV_REQUEST,
        .response_addr = std.math.maxInt(usize),
        .response_len = std.math.maxInt(usize),
    }, &key) catch reject(index);
    if (key.sequence <= previous_close_sequence) reject(index);
    if (runtime.execution.acknowledgeOwnedRootReturn(ticket)) |_| reject(index) else |err| {
        if (err != error.SyscallInFlight) reject(index);
    }
    @atomicStore(u8, &cpus[index].broker_close_published, 1, .release);
    if (!smp.notifySyscallRequest()) reject(index);
    while (@atomicLoad(u32, &broker_phase, .acquire) != BROKER_CLOSE_REPLY or
        @atomicLoad(u32, &cpus[index].broker_completion_count, .acquire) <= close_completions) brokerWait(index, &snapshot);
    runtime.execution.consumeSyscallInto(key, &reply) catch reject(index);
    var after_close: dispatch_ownership.BoundIdentity = undefined;
    runtime.execution.boundIdentityInto(ticket, &after_close) catch reject(index);
    if (reply.status != @backingInt(abi.SyscallStatus.success) or reply.denial_reason != @backingInt(abi.DenialReason.none) or
        reply.bytes_written != 0 or !runtime.execution.syscallIdle(ticket) or runtime.execution.stopRequested(ticket) or
        !std.meta.eql(after_close, bound) or !paging.kernelAddressSpaceActive() or
        x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3 or !brokerOutputsAreCanary(space, index, 3) or
        @atomicLoad(u32, &cpus[index].broker_stop_count, .acquire) != 0 or
        @atomicLoad(u32, &cpus[index].broker_tlb_count, .acquire) != 1) reject(index);
    // Closing a channel is not task return. No user output or resource access
    // after a later execution ACK is needed to substantiate this receipt.
    @atomicStore(u8, &cpus[index].broker_close_consumed, 1, .release);
    while (@atomicLoad(u32, &broker_phase, .acquire) != BROKER_TERMINATE_REQUEST) brokerWait(index, &snapshot);
    const previous_sequence = key.sequence;
    const completion_count = @atomicLoad(u32, &cpus[index].broker_completion_count, .acquire);
    runtime.execution.submitSyscallInto(ticket, .{
        .opcode = abi.opcode(.task_terminate),
        .request_addr = BROKER_REQUEST,
        .response_addr = std.math.maxInt(usize),
        .response_len = std.math.maxInt(usize),
    }, &key) catch reject(index);
    if (key.sequence <= previous_sequence) reject(index);
    if (runtime.execution.acknowledgeOwnedRootReturn(ticket)) |_| reject(index) else |err| {
        if (err != error.SyscallInFlight) reject(index);
    }
    @atomicStore(u8, &cpus[index].broker_published, 1, .release);
    if (!smp.notifySyscallRequest()) reject(index);
    while (@atomicLoad(u32, &broker_phase, .acquire) != BROKER_TERMINATE_REPLY or
        @atomicLoad(u32, &cpus[index].broker_completion_count, .acquire) <= completion_count) brokerWait(index, &snapshot);
    runtime.execution.consumeSyscallInto(key, &reply) catch reject(index);
    if (reply.status != @backingInt(abi.SyscallStatus.success) or reply.denial_reason != @backingInt(abi.DenialReason.none) or
        reply.bytes_written != 0 or !runtime.execution.syscallIdle(ticket) or !runtime.execution.stopRequested(ticket) or
        @atomicLoad(u32, &cpus[index].broker_stop_count, .acquire) != 1 or
        @atomicLoad(u32, &cpus[index].broker_tlb_count, .acquire) != 1) reject(index);
    @atomicStore(u8, &cpus[index].broker_consumed, 1, .release);
    while (@atomicLoad(u8, &dispatch_return_target, .acquire) != index) brokerWait(index, &snapshot);
    if (!paging.kernelAddressSpaceActive() or x86.interruptsEnabled() or !runtime.execution.syscallIdle(ticket)) reject(index);
    native_entry.clearContinuation();
    entry.active_task_id = 0;
    if (entry.userspace_xstate != 0 or entry.kernel_xstate != 0 or entry.resume_rsp != 0 or
        entry.resume_rip != 0 or entry.resume_requested != 0) reject(index);
    runtime.execution.acknowledgeOwnedRootReturn(ticket) catch reject(index);
    @atomicStore(u8, &cpus[index].broker_returned, 1, .release);
    while (@atomicLoad(u32, &broker_phase, .acquire) != BROKER_DONE) asm volatile ("pause");
}

fn waitForStopPhase(phase: u32) void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    for (cpus[1..]) |*cpu| {
        while (@atomicLoad(u32, &cpu.stop_completed, .acquire) != phase) {
            if (@atomicLoad(u8, &cpu.status, .acquire) != 1 or deadline.expired())
                proof.fail("SMP stop interrupt return timeout");
            asm volatile ("pause");
        }
    }
}

fn holdPrivateRoot(index: u8) void {
    while (@atomicLoad(u32, &root_phase, .acquire) != 1) asm volatile ("pause");
    const runtime = dispatch_runtime orelse reject(index);
    const ticket = dispatch_tickets[index - 1];
    const bound = runtime.execution.start(ticket) catch reject(index);
    const private = &private_roots[index - 1];
    if (bound.identity.task_id != dispatch_task_ids[index - 1] or
        bound.identity.address_space_id != dispatch_address_ids[index - 1] or
        bound.mapping_handle != index or bound.physical_root != private.switch_cr3 & x86.CR3_ADDRESS_MASK) reject(index);
    paging.switchToUserAddressSpace(private);
    if (x86.interruptsEnabled() or paging.getCurrentPageDirectory() != private.directory or
        x86.readCr3() != private.switch_cr3 & ~x86.CR3_NO_FLUSH or paging.kernelAddressSpaceActive() or
        paging.currentPagePermissions(startup_physical) != null or !verifyCurrentGs(index, true)) reject(index);
    @atomicStore(u32, &cpus[index].root_phase_completed, 1, .release);
    awaitStopPrompts(index, runtime, ticket, private);
    while (@atomicLoad(u32, &root_phase, .acquire) != 2) asm volatile ("pause");
    if (!runtime.execution.stopRequested(ticket)) reject(index);
    while (@atomicLoad(u8, &dispatch_return_target, .acquire) != index) asm volatile ("pause");
    paging.switchToKernelAddressSpace();
    const kernel: *paging.PageDirectory = @ptrFromInt(paging.directMapAddress(physical_cr3) orelse reject(index));
    if (x86.interruptsEnabled() or paging.getCurrentPageDirectory() != kernel or
        x86.readCr3() & x86.CR3_ADDRESS_MASK != physical_cr3 or !paging.kernelAddressSpaceActive() or
        !verifyCurrentGs(index, true)) reject(index);
    // Native entry stays dormant in this CPL0 fixture. Clear only the owned
    // continuation and end all private-root accesses before release ack.
    native_entry.clearContinuation();
    const entry = native_entry.current();
    entry.active_task_id = 0;
    if (entry.active_task_id != 0 or entry.userspace_xstate != 0 or entry.kernel_xstate != 0 or
        entry.resume_rsp != 0 or entry.resume_rip != 0 or entry.resume_requested != 0) reject(index);
    runtime.execution.acknowledgeOwnedRootReturn(ticket) catch reject(index);
    @atomicStore(u32, &cpus[index].root_phase_completed, 2, .release);
}

fn runGlobalTlbProof() void {
    if (paging.currentPagePermissions(WITNESS_ADDRESS) != null) proof.fail("SMP witness collision");
    const first = paging.allocGeneralFrame() orelse proof.fail("SMP first witness frame");
    const second = paging.allocGeneralFrame() orelse proof.fail("SMP second witness frame");
    const first_alias: *volatile u64 = @ptrFromInt(paging.directMapAddress(first) orelse proof.fail("SMP first witness alias"));
    const second_alias: *volatile u64 = @ptrFromInt(paging.directMapAddress(second) orelse proof.fail("SMP second witness alias"));
    first_alias.* = WITNESS_A;
    second_alias.* = WITNESS_B;
    x86.writeCr4(x86.readCr4() | x86.CR4_PGE);
    const flags = paging.PAGE_PRESENT | paging.PAGE_WRITABLE;
    paging.mapKernelBorrowedPage(WITNESS_ADDRESS, @intCast(first), flags);
    requireGlobalWitness(first, WITNESS_A);
    @atomicStore(u32, &irq_phase, 1, .release);
    waitForApPhase(.ready, 1);
    paging.setRemoteKernelShootdown(smp.shootdownKernel);
    // These are actual production pager mutations. Each publishes the new
    // GLOBAL leaf, invalidates this BSP, then waits for every remote CPU.
    paging.mapKernelBorrowedPage(WITNESS_ADDRESS, @intCast(second), flags);
    requireGlobalWitness(second, WITNESS_B);
    waitForApPhase(.completed, 1);
    @atomicStore(u32, &irq_phase, 2, .release);
    waitForApPhase(.ready, 2);
    paging.mapKernelBorrowedPage(WITNESS_ADDRESS, @intCast(first), flags);
    requireGlobalWitness(first, WITNESS_A);
    waitForApPhase(.completed, 2);
    for (cpus[1..]) |*cpu| {
        if (@atomicLoad(u32, &cpu.irq_count, .acquire) != 2 or
            @atomicLoad(u8, &cpu.irq_environment_invalid, .acquire) != 0) proof.fail("SMP exact IPI dispatch");
    }
    proof.pass("SMP_IPI_STATE");
    proof.pass("SMP_GLOBAL_TLB");
    runDeviceCacheProof();
    // The bound CPUs and both borrowed witness frames remain alive until the
    // emulator exits. There is no hotplug/quiescence protocol in this fixture.
}

const Leaf = struct {
    entry: u64,
    shift: u6,

    fn physical(self: @This(), virtual: usize) u64 {
        const mask = (@as(u64, 1) << self.shift) - 1;
        return (table.address(self.entry) & ~mask) | (@as(u64, virtual) & mask);
    }

    fn attributes(self: @This()) u64 {
        const mask = table.PRESENT | table.WRITABLE | table.USER | table.WRITE_THROUGH | table.CACHE_DISABLE |
            table.GLOBAL | table.NO_EXECUTE;
        const pat_shift: u6 = if (self.shift == table.PAGE_TABLE_SHIFT) 7 else 12;
        return (self.entry & mask) | ((self.entry >> pat_shift & 1) << 52);
    }
};

fn readLeaf(virtual: usize) ?Leaf {
    var current: *const table.Table = paging.getCurrentPageDirectory();
    for ([_]u6{ table.PML4_SHIFT, table.PDPT_SHIFT, table.PAGE_DIRECTORY_SHIFT, table.PAGE_TABLE_SHIFT }) |shift| {
        const entry = @atomicLoad(u64, &current[table.index(virtual, shift)], .acquire);
        if (!table.isPresent(entry)) return null;
        if (shift == table.PAGE_TABLE_SHIFT or (shift != table.PML4_SHIFT and table.isLargePage(entry)))
            return .{ .entry = entry, .shift = shift };
        current = @ptrFromInt(paging.directMapAddress(table.address(entry)) orelse proof.fail("cache proof table alias"));
    }
    return null;
}

fn requireDeviceLeaves(phase: usize) void {
    const physical = DEVICE_PHYSICAL[phase];
    const cache_bits = table.WRITE_THROUGH | table.CACHE_DISABLE;
    for (0..2) |page| {
        const offset = page * PAGE_BYTES;
        const virtual = DEVICE_WITNESS_ADDRESS + offset;
        const leaf = readLeaf(virtual) orelse proof.fail("device cache destination absent");
        if (leaf.shift != table.PAGE_TABLE_SHIFT or leaf.physical(virtual) != physical + offset or
            leaf.entry & cache_bits != cache_bits or leaf.entry & (table.USER | (1 << 7)) != 0 or
            leaf.entry & table.NO_EXECUTE == 0 or (leaf.entry & table.WRITABLE != 0) != (phase == 0))
            proof.fail("device strict UC supervisor leaf");
        const direct = paging.directMapAddress(physical + offset) orelse proof.fail("device direct alias geometry");
        if (readLeaf(direct) != null) proof.fail("device WB direct alias present");
    }
}

fn runDeviceCacheProof() void {
    paging.setDeviceAliasTransition(smp.beginDeviceAliasTransition, smp.flushDeviceAliasTransition, smp.endDeviceAliasTransition);
    if (readLeaf(DEVICE_WITNESS_ADDRESS) != null or readLeaf(DEVICE_WITNESS_ADDRESS + PAGE_BYTES) != null)
        proof.fail("device cache scratch collision");
    const forbidden = paging.allocGeneralFrame() orelse proof.fail("device cache negative frame");
    const stats = paging.frameStats();
    if (paging.mapKernelDeviceRange(DEVICE_WITNESS_ADDRESS, forbidden, PAGE_BYTES, true)) |_| {
        proof.fail("allocated RAM admitted as device");
    } else |_| {}
    if (readLeaf(DEVICE_WITNESS_ADDRESS) != null or !std.meta.eql(stats, paging.frameStats()))
        proof.fail("device cache rejection changed mapping or frames");
    paging.releaseGeneralFrame(forbidden) catch proof.fail("device cache negative frame reclaim");
    for (DEVICE_PHYSICAL, 0..) |physical, phase| {
        // These device gaps are outside the 256MiB guest RAM. Sparse bootstrap
        // must already omit both WB direct aliases. This phase proves actual
        // strict-UC publication followed by an actual held cache/IPI barrier,
        // then retirement of changed UC leaves through the real global TLB
        // protocol. It does not claim a guest transition from a former blanket
        // WB device mapping. Inspect mappings only: never access MMIO bytes.
        for (0..2) |page| {
            const direct = paging.directMapAddress(physical + page * PAGE_BYTES) orelse proof.fail("device initial direct geometry");
            if (readLeaf(direct) != null) proof.fail("device initial WB direct alias");
        }
        const lower = paging.directMapAddress(physical - PAGE_BYTES) orelse proof.fail("device lower neighbor");
        const upper = paging.directMapAddress(physical + 2 * PAGE_BYTES) orelse proof.fail("device upper neighbor");
        const before = [_]?Leaf{ readLeaf(lower), readLeaf(upper) };
        const addresses = [_]usize{ lower, upper };
        @atomicStore(u32, &cache_phase, @intCast(phase + 1), .release);
        waitForCacheApPhase(false, @intCast(phase + 1));
        paging.mapKernelDeviceRange(DEVICE_WITNESS_ADDRESS, physical, 2 * PAGE_BYTES, phase == 0) catch proof.fail("device cache transaction");
        if (phase == 0) {
            // Fresh sparse UC leaves have no prior alias/translation to retire,
            // so the mapper correctly sends no IPI. Exercise the actual cache
            // rendezvous separately after publication; no allocation or paging
            // operation occurs while its AP handlers are held. The second map
            // replaces present UC leaves and performs its own global shootdown.
            smp.beginDeviceAliasTransition();
            smp.flushDeviceAliasTransition();
            smp.endDeviceAliasTransition();
        }
        requireDeviceLeaves(phase);
        for (addresses, before) |virtual, original| {
            const after = readLeaf(virtual);
            if (original) |previous| {
                const present = after orelse proof.fail("device cache neighbor removed");
                if (present.physical(virtual) != previous.physical(virtual) or present.attributes() != previous.attributes())
                    proof.fail("device cache neighbor changed");
            } else if (after != null) proof.fail("device gap neighbor populated");
        }
        // A same-cache UC remap acknowledges the cleared old translations
        // before publishing its new leaves. IRET is not that publication; AP
        // leaf inspection waits for this separate release after map returns.
        @atomicStore(u32, &cache_publication, @intCast(phase + 1), .release);
        waitForCacheApPhase(true, @intCast(phase + 1));
    }
    for (cpus[1..]) |*cpu| {
        if (@atomicLoad(u32, &cpu.irq_count, .acquire) != 4 or
            @atomicLoad(u8, &cpu.irq_environment_invalid, .acquire) != 0) proof.fail("device cache exact IPI count");
    }
    proof.pass("SMP_DEVICE_CACHE");
}

fn waitForCacheApPhase(completed: bool, phase: u32) void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    for (cpus[1..]) |*cpu| {
        const field = if (completed) &cpu.cache_completed else &cpu.cache_ready;
        while (@atomicLoad(u32, field, .acquire) != phase) {
            if (@atomicLoad(u8, &cpu.status, .acquire) != 1 or deadline.expired()) proof.fail("device cache AP phase");
            asm volatile ("pause");
        }
    }
}

const PhasePublication = enum { ready, completed };

fn waitForApPhase(publication: PhasePublication, phase: u32) void {
    const deadline = tsc_clock.afterMilliseconds(2000);
    for (cpus[1..]) |*cpu| {
        const field = if (publication == .ready) &cpu.irq_ready else &cpu.irq_completed;
        while (@atomicLoad(u32, field, .acquire) != phase) {
            if (@atomicLoad(u8, &cpu.status, .acquire) != 1) proof.fail("SMP IPI state or witness");
            if (deadline.expired()) proof.fail("SMP IPI phase timeout");
            asm volatile ("pause");
        }
    }
}

fn requireGlobalWitness(physical: u64, expected_value: u64) void {
    if (!x86.globalPagesEnabled()) proof.fail("SMP global pages disabled");
    var current: *const table.Table = @ptrFromInt(paging.directMapAddress(physical_cr3) orelse proof.fail("SMP witness root"));
    for ([_]u6{ table.PML4_SHIFT, table.PDPT_SHIFT, table.PAGE_DIRECTORY_SHIFT }) |shift| {
        const entry = current[table.index(WITNESS_ADDRESS, shift)];
        if (!table.isPresent(entry) or table.isLargePage(entry) or entry & table.USER != 0) proof.fail("SMP witness hierarchy");
        current = @ptrFromInt(paging.directMapAddress(table.address(entry)) orelse proof.fail("SMP witness table"));
    }
    const leaf = current[table.index(WITNESS_ADDRESS, table.PAGE_TABLE_SHIFT)];
    const expected = table.PRESENT | table.WRITABLE | table.GLOBAL | table.NO_EXECUTE;
    if (leaf & expected != expected or leaf & table.USER != 0 or table.address(leaf) != physical) proof.fail("SMP global witness leaf");
    const value: *const volatile u64 = @ptrFromInt(WITNESS_ADDRESS);
    if (value.* != expected_value) proof.fail("SMP BSP changed witness");
}

fn maskLocalInterruptSources() void {
    const version = x86.readMsr(0x803);
    const max_lvt: u8 = @truncate(version >> 16);
    if (max_lvt < 5) proof.fail("SMP local APIC LVT bound");
    // Timer, thermal, performance, both LINT pins and error sources are masked;
    // CMCI exists only when the APIC advertises that seventh LVT entry.
    for ([_]u32{ 0x832, 0x833, 0x834, 0x835, 0x836, 0x837 }) |msr|
        x86.writeMsr(msr, x86.readMsr(msr) | (1 << 16));
    if (max_lvt >= 6) x86.writeMsr(0x82f, x86.readMsr(0x82f) | (1 << 16));
}

pub export fn zigos_arch_smp_handle_execution_stop_ipi() callconv(.c) void {
    // Share the production vector's sole EOI body. This isolated CPL0 gate
    // observes the owner-local Coordinator only; it cannot hand off a user or
    // publish an execution acknowledgement.
    isr.acknowledgeExecutionStopInterrupt();
    const index = cpu_identity.currentIndex();
    if (index == 0 or index >= PROOF_CPU_COUNT) park();
    const runtime = dispatch_runtime orelse return;
    const ticket = dispatch_tickets[index - 1];
    if (@atomicLoad(u32, &broker_phase, .acquire) != 0) {
        if (!brokerInterruptEnvironment() or ticket.cpu != index or ticket.issuer != &runtime.execution or
            !runtime.execution.stopRequested(ticket)) reject(index);
        _ = @atomicRmw(u32, &cpus[index].broker_stop_count, .Add, 1, .release);
        return;
    }
    const flags = asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> usize),
    );
    var x87_control: u16 = undefined;
    var mxcsr: u32 = undefined;
    asm volatile ("fnstcw %[control]"
        : [control] "=m" (x87_control),
    );
    asm volatile ("stmxcsr %[control]"
        : [control] "=m" (mxcsr),
    );
    const count = @atomicLoad(u32, &cpus[index].stop_count, .acquire);
    if (flags & (FLAG_DF | FLAG_AC) != 0 or x86.interruptsEnabled() or
        x87_control != 0x037f or mxcsr != 0x1f80 or ticket.cpu != index or ticket.issuer != &runtime.execution or
        count >= 3 or x86.readCr3() & x86.CR3_ADDRESS_MASK != private_roots[index - 1].switch_cr3 & x86.CR3_ADDRESS_MASK)
        @atomicStore(u8, &cpus[index].stop_environment_invalid, 1, .release);
    if (count < 3 and runtime.execution.stopRequested(ticket))
        _ = @atomicRmw(u8, &cpus[index].stop_observations, .Or, @as(u8, 1) << @as(u3, @intCast(count)), .release);
    _ = @atomicRmw(u32, &cpus[index].stop_count, .Add, 1, .release);
}

fn awaitStopPrompts(index: u8, runtime: *task_runtime.Runtime, ticket: dispatch_ownership.Ticket, private: *paging.UserAddressSpace) void {
    const cpu = &cpus[index];
    model.initialize(&cpu.seed, index % 3);
    for (1..4) |phase_value| {
        const phase: u32 = @intCast(phase_value);
        model.initializeCanary(&cpu.restored);
        while (true) {
            var restored_flags: usize = 0;
            const gp_match = zigos_arch_smp_wait_for_ipi(&cpu.seed, &cpu.restored, &restored_flags);
            if (gp_match != 1 or restored_flags & (FLAG_DF | FLAG_AC) != FLAG_DF | FLAG_AC or
                !verifyRestoredState(&cpu.seed, &cpu.restored) or x86.interruptsEnabled() or
                !verifyCurrentGs(index, true) or paging.getCurrentPageDirectory() != private.directory or
                x86.readCr3() & x86.CR3_ADDRESS_MASK != private.switch_cr3 & x86.CR3_ADDRESS_MASK)
                reject(index);
            const count = @atomicLoad(u32, &cpu.stop_count, .acquire);
            if (count < phase) continue; // A spurious interrupt carries no STOP authority.
            const expected: u8 = if (phase == 1) 0 else if (phase == 2) 2 else 6;
            if (count != phase or @atomicLoad(u8, &cpu.stop_observations, .acquire) != expected or
                @atomicLoad(u8, &cpu.stop_environment_invalid, .acquire) != 0 or
                runtime.execution.stopRequested(ticket) != (phase > 1)) reject(index);
            break;
        }
        // Publish only after IRET, complete register/flag checks and unchanged
        // root/continuation ownership. This still is not an execution ACK.
        @atomicStore(u32, &cpu.stop_completed, phase, .release);
    }
}

pub export fn zigos_arch_smp_handle_tlb_ipi() callconv(.c) void {
    const index = cpu_identity.currentIndex();
    if (index == 0 or index >= PROOF_CPU_COUNT) park();
    if (@atomicLoad(u32, &broker_phase, .acquire) == 1) {
        if (!brokerInterruptEnvironment()) reject(index);
        smp.handleTlbIpi();
        _ = @atomicRmw(u32, &cpus[index].broker_tlb_count, .Add, 1, .release);
        return;
    }
    const flags = asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> usize),
    );
    var x87_control: u16 = undefined;
    var mxcsr: u32 = undefined;
    asm volatile ("fnstcw %[control]"
        : [control] "=m" (x87_control),
    );
    asm volatile ("stmxcsr %[control]"
        : [control] "=m" (mxcsr),
    );
    if (flags & (FLAG_DF | FLAG_AC) != 0 or x86.interruptsEnabled() or
        x87_control != 0x037f or mxcsr != 0x1f80 or !x86.globalPagesEnabled())
        @atomicStore(u8, &cpus[index].irq_environment_invalid, 1, .release);
    smp.handleTlbIpi();
    _ = @atomicRmw(u32, &cpus[index].irq_count, .Add, 1, .release);
}

fn brokerInterruptEnvironment() bool {
    const flags = asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> usize),
    );
    var x87_control: u16 = undefined;
    var mxcsr: u32 = undefined;
    asm volatile ("fnstcw %[control]"
        : [control] "=m" (x87_control),
    );
    asm volatile ("stmxcsr %[control]"
        : [control] "=m" (mxcsr),
    );
    return flags & (FLAG_DF | FLAG_AC) == 0 and !x86.interruptsEnabled() and
        x87_control == 0x037f and mxcsr == 0x1f80 and paging.kernelAddressSpaceActive() and
        x86.readCr3() & x86.CR3_ADDRESS_MASK == physical_cr3;
}

pub export fn zigos_arch_smp_handle_syscall_request_ipi() callconv(.c) void {
    isr.acknowledgeSyscallRequestInterrupt();
    const index = cpu_identity.currentIndex();
    if (index != 0 or !brokerInterruptEnvironment()) reject(index);
    _ = @atomicRmw(u32, &broker_request_count, .Add, 1, .release);
}

pub export fn zigos_arch_smp_handle_syscall_completion_ipi() callconv(.c) void {
    isr.acknowledgeSyscallCompletionInterrupt();
    const index = cpu_identity.currentIndex();
    if (index == 0 or index >= PROOF_CPU_COUNT or !brokerInterruptEnvironment()) reject(index);
    _ = @atomicRmw(u32, &cpus[index].broker_completion_count, .Add, 1, .release);
}

pub export fn zigos_arch_smp_handle_prepared_execution_ipi() callconv(.c) void {
    // The actual immutable handler acknowledges and publishes only a selected
    // coalesced hint. The ISR never resolves a queue/source/Runtime command.
    isr.acknowledgePreparedExecutionInterrupt();
    const index = cpu_identity.currentIndex();
    if (index != PREPARED_OWNER_CPU or !brokerInterruptEnvironment() or gsEntryModes() != 0 or
        @atomicLoad(u32, &zigos_arch_smp_prepared_ipi_window, .acquire) != 1) reject(index);
    _ = @atomicRmw(u32, &prompted_ipi_count, .Add, 1, .release);
}

fn serviceIpis(index: u8) noreturn {
    const cpu = &cpus[index];
    model.initialize(&cpu.seed, index % 3);
    const witness: *const volatile u64 = @ptrFromInt(WITNESS_ADDRESS);
    for (1..3) |phase_value| {
        const phase: u32 = @intCast(phase_value);
        while (@atomicLoad(u32, &irq_phase, .acquire) != phase) asm volatile ("pause");
        const old = if (phase == 1) WITNESS_A else WITNESS_B;
        const changed = if (phase == 1) WITNESS_B else WITNESS_A;
        if (!x86.globalPagesEnabled() or witness.* != old) reject(index);
        model.initializeCanary(&cpu.restored);
        @atomicStore(u32, &cpu.irq_ready, phase, .release);
        while (true) {
            var restored_flags: usize = 0;
            const gp_match = zigos_arch_smp_wait_for_ipi(&cpu.seed, &cpu.restored, &restored_flags);
            if (gp_match != 1 or restored_flags & (FLAG_DF | FLAG_AC) != FLAG_DF | FLAG_AC or
                !verifyRestoredState(&cpu.seed, &cpu.restored)) reject(index);
            const count = @atomicLoad(u32, &cpu.irq_count, .acquire);
            if (count < phase) continue; // Harmless spurious-vector wakeup.
            if (count != phase or witness.* != changed or
                @atomicLoad(u8, &cpu.irq_environment_invalid, .acquire) != 0) reject(index);
            break;
        }
        // Production acknowledgement precedes IRET. This extra release only
        // publishes after return, state checks and the changed-page read.
        @atomicStore(u32, &cpu.irq_completed, phase, .release);
    }
    for (0..DEVICE_PHYSICAL.len) |phase| {
        const publication: u32 = @intCast(phase + 1);
        const expected_count: u32 = @intCast(phase + 3);
        while (@atomicLoad(u32, &cache_phase, .acquire) != publication) asm volatile ("pause");
        @atomicStore(u32, &cpu.cache_ready, publication, .release);
        while (true) {
            model.initializeCanary(&cpu.restored);
            var restored_flags: usize = 0;
            const gp_match = zigos_arch_smp_wait_for_ipi(&cpu.seed, &cpu.restored, &restored_flags);
            if (gp_match != 1 or restored_flags & (FLAG_DF | FLAG_AC) != FLAG_DF | FLAG_AC or
                !verifyRestoredState(&cpu.seed, &cpu.restored)) reject(index);
            const count = @atomicLoad(u32, &cpu.irq_count, .acquire);
            if (count < expected_count) continue;
            if (count != expected_count) reject(index);
            const deadline = tsc_clock.afterMilliseconds(2000);
            while (@atomicLoad(u32, &cache_publication, .acquire) != publication) {
                if (deadline.expired()) reject(index);
                asm volatile ("pause");
            }
            requireDeviceLeaves(phase);
            break;
        }
        @atomicStore(u32, &cpu.cache_completed, publication, .release);
    }
    park();
}

fn verifyRestoredState(seed: *const model.Image, restored: *const model.Image) bool {
    const before = &seed.state.image;
    const after = &restored.state.image;
    if (!std.mem.eql(u8, before[0..5], after[0..5]) or
        !std.mem.eql(u8, before[24..28], after[24..28])) return false;
    for (0..8) |register| {
        const offset = 32 + register * 16;
        if (!std.mem.eql(u8, before[offset..][0..10], after[offset..][0..10])) return false;
    }
    if (!std.mem.eql(u8, before[160..416], after[160..416]) or
        !std.mem.eql(u8, before[576..832], after[576..832]) or
        std.mem.readInt(u64, after[512..520], .little) != 7 or
        std.mem.readInt(u64, after[520..528], .little) != 0 or restored.state.pkru != 0 or restored.state.reserved != 0) return false;
    for (std.mem.asBytes(restored)[@sizeOf(@TypeOf(restored.state))..]) |byte| {
        if (byte != 0xa5) return false;
    }
    return true;
}

fn observe(index: u8, entry_cr4: usize) ?Observation {
    if (cpu_identity.currentIndex() != index or x86.readMsr(x86.IA32_TSC_AUX_MSR) != index or
        !x86.lassAddressPartitionSupported() or !x86.supervisorAccessPreventionEnabled() or
        x86.readCr4() & (x86.CR4_LASS | x86.CR4_FRED) != 0 or x86.interruptsEnabled()) return null;
    const flags = asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> usize),
    );
    if (flags & (1 << 18) != 0) return null;
    var gdtr: gdt.GdtPtr = undefined;
    asm volatile ("sgdt (%[table])"
        :
        : [table] "r" (&gdtr),
        : .{ .memory = true });
    const selector = asm volatile ("str %[selector]"
        : [selector] "=r" (-> u16),
    );
    if (selector != gdt.TSS_SEG or gdtr.limit != 55 or !@import("../cpu_baseline.zig").isCanonicalUpperHalf(gdtr.base)) return null;
    const descriptors: *const [7]u64 = @ptrFromInt(gdtr.base);
    const low = descriptors[5];
    const high = descriptors[6];
    const tss_base = ((low >> 16) & 0xFF_FFFF) | ((low >> 32) & 0xFF00_0000) | (high << 32);
    if ((low >> 40) & 0xFF != 0x8B or high >> 32 != 0 or
        (low & 0xFFFF) | ((low >> 32) & 0xF0000) != @sizeOf(gdt.Tss) - 1 or
        !@import("../cpu_baseline.zig").isCanonicalUpperHalf(tss_base)) return null;
    const tss: *const gdt.Tss = @ptrFromInt(tss_base);
    if (tss.iomap_base != @sizeOf(gdt.Tss)) return null;
    const instruction = asm volatile ("lea 0(%%rip), %[value]"
        : [value] "=r" (-> usize),
    );
    return .{
        .instruction = instruction,
        .stack_pointer = x86.stackPointer(),
        .physical_cr3 = x86.readCr3() & x86.CR3_ADDRESS_MASK,
        .entry_cr4 = entry_cr4,
        .gdt_base = gdtr.base,
        .tss_base = tss_base,
        .ring_stack_top = tss.rsp0,
        .emergency_stack_top = tss.ist1,
        .gs_base = @intCast(x86.readMsr(x86.IA32_GS_BASE_MSR)),
        .trap_stack_top = native_executor.prepareKernelStack(),
        .logical_cpu = cpu_identity.currentIndex(),
        .apic_id = x2apic.localId(),
    };
}

fn apEntry(cpu_index: u64) callconv(.c) noreturn {
    // Capture the assembly handoff before any identity or runtime feature
    // activation. The bridge must not inherit this BSP's modern CR4 bits.
    const entry_cr4 = x86.readCr4();
    const index = std.math.cast(u8, cpu_index) orelse park();
    if (index == 0 or index >= PROOF_CPU_COUNT) park();
    if (entry_cr4 != AP_ENTRY_CR4) reject(index);
    const ap_features = features.detect();
    if (!ap_features.rdpid or !ap_features.x2apic or !ap_features.smap or !ap_features.pge) reject(index);
    features.admitApplicationProcessorCache() catch |err| {
        inline for (@typeInfo(features.CacheAdmissionError).error_set.error_names.?) |cause| {
            if (err == @field(features.CacheAdmissionError, cause)) proof.fail("SMP cache: " ++ cause);
        }
        unreachable;
    };
    cpu_identity.initialize(index);
    paging.initializeCurrentKernelRoot();
    x86.writeCr4(entry_cr4 | x86.CR4_SMAP);
    x86.forbidSupervisorUserMemory();
    // Invalidate this CPU's cached low leaf before publishing that it has
    // permanently reached high code and the bridge may be patched or retired.
    x86.invalidatePage(startup_physical);
    gdt.initCpu(index);
    gdt.setKernelStack(cpus[index].stack_top);
    idt.init();
    x2apic.enable();
    var timer_features = ap_features;
    timer_features.tsc_frequency_hz = PROOF_TSC_FREQUENCY_HZ;
    if (!timer.initApplicationProcessor(timer_features)) reject(index);
    timer.synchronize();
    touchSelectedTrapStack(index);
    proveColdStackOwner(index);
    bindProofContinuation(index);
    cpus[index].observation = observe(index, entry_cr4) orelse reject(index);
    cpus[index].observation.timer = observeTimer(ap_features.tsc_deadline);
    x86.writeCr4(x86.readCr4() | x86.CR4_PGE);
    maskLocalInterruptSources();
    @atomicStore(u8, &cpus[index].status, 1, .release);
    checkOwnTimer(index);
    clearOwnContinuation(index);
    holdPrivateRoot(index);
    holdBrokerRequest(index);
    holdPreparedOwner(index);
    holdPreparedTransport(index);
    holdPromptedPreparedTransport(index);
    holdGuardedTrapStack(index);
    if (comptime @import("mapping_xstate_probe.zig").enabled)
        @import("mapping_xstate_probe.zig").hold(index, cpus[index].trap_stack_top, cpus[index].stack_guard + PAGE_BYTES, cpus[index].stack_top);
    serviceIpis(index);
}

fn reject(index: u8) noreturn {
    @atomicStore(u8, &cpus[index].status, 2, .release);
    park();
}

fn park() noreturn {
    x86.cli();
    while (true) x86.hlt();
}

fn waitMilliseconds(milliseconds: u64) void {
    const deadline = tsc_clock.afterMilliseconds(milliseconds);
    while (!deadline.expired()) asm volatile ("pause");
}
