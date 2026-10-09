// A separate, fixed-topology CPL0 instruction oracle. Raw capability absence
// exits before the ordinary high-half fixture starts; it is never a PASS.
const std = @import("std");
const root = @import("root");
const x86 = @import("../x86.zig");
const address = @import("../kernel_address.zig");
const xstate = @import("../xstate.zig");
const model = @import("mapping_xstate_probe_model.zig");
const native_entry = @import("native_entry_state.zig");
const cpu_identity = @import("../../kernel/cpu_identity.zig");
const executor = @import("../../native/task/userspace_executor.zig");
const scheduler_module = @import("../../native/task/userspace_scheduler.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const ownership = @import("../../native/task/dispatch_ownership.zig");
const transport = @import("../../native/task/dispatch_transport.zig");
const table_backing = @import("../../native/core/table_backing.zig");
const paging = @import("../../kernel/memory/paging64.zig");
const clock = @import("../../kernel/timer/tsc_clock.zig");
const console = @import("../../kernel/utils/console.zig");
const proof = @import("high_half_probe.zig");

pub const enabled = @hasDecl(root, "MAPPING_XSTATE_PROOF") and root.MAPPING_XSTATE_PROOF;
const OWNER: u8 = 1;
const EPOCHS = 4;
const DONE: u32 = EPOCHS + 1;
const Cpuid = struct { eax: u32, ebx: u32, ecx: u32, edx: u32 };

extern fn zigos_mapping_xstate_roundtrip(*align(64) xstate.State, *const model.Image, *const model.Image, *model.Result, u32) callconv(.c) void;

var phase: u32 = 0;
var owner_ready: u32 = 0;
var returned_phase: u32 = 0;
var completed_phase: u32 = 0;
var release_phase: u32 = 0;
var owner_phase: u32 = 0;
var callback_count: u32 = 0;
var owner_ran: bool = false;
var states: [2]*align(64) xstate.State = undefined;
var storages: [2]*xstate.Storage = undefined;
var task_ids: [2]u64 = undefined;
var roots: [2]u64 = undefined;
var contexts: [2]executor.UserContext64 = undefined;
var seeds: [3]model.Image = undefined;
var poison: model.Image = undefined;
var results: [EPOCHS]model.Result = undefined;
var neighbor_state: xstate.State = undefined;
var neighbors: [16]native_entry.State = undefined;
var stack_hashes: [16]u64 = undefined;

fn cpuid(leaf: u32, subleaf: u32) Cpuid {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

fn rawCapabilities() model.Capabilities {
    const maximum = cpuid(0, 0).eax;
    var caps: model.Capabilities = .{ .maximum_leaf = maximum, .leaf1_ecx = 0, .state_mask = 0, .state_features = 0, .ymm_bytes = 0, .ymm_offset = 0, .ymm_flags = 0 };
    if (maximum >= 1) caps.leaf1_ecx = cpuid(1, 0).ecx;
    if (maximum >= 0xD) {
        caps.state_mask = cpuid(0xD, 0).eax;
        caps.state_features = cpuid(0xD, 1).eax;
        const ymm = cpuid(0xD, 2);
        caps.ymm_bytes = ymm.eax;
        caps.ymm_offset = ymm.ebx;
        caps.ymm_flags = ymm.ecx;
    }
    return caps;
}

pub fn preflightBsp() void {
    if (rawCapabilities().unsupported()) |reason| {
        console.print("ZIGOS:ARCH:X86_64:MAPPING_XSTATE:UNSUPPORTED:");
        console.print(@tagName(reason));
        console.print("\n");
        x86.outl(0xF4, 0x12);
        while (true) asm volatile ("cli; hlt");
    }
    pass("BSP_ADMISSION");
}

fn pass(comptime stage: []const u8) void {
    console.print("ZIGOS:ARCH:X86_64:MAPPING_XSTATE:" ++ stage ++ ":PASS\n");
}

fn wait(word: *const u32, wanted: u32) void {
    const deadline = clock.afterMilliseconds(2000);
    while (@atomicLoad(u32, word, .acquire) != wanted) {
        if (deadline.expired()) proof.fail("Mapping xstate phase timeout");
        asm volatile ("pause");
    }
}

fn borrowCount(runtime: *const task_runtime.Runtime) u32 {
    var count: u32 = 0;
    for (runtime.task_borrow_counts) |value| count += value;
    return count;
}

fn stackHash(top: usize) u64 {
    const bytes: [*]const volatile u8 = @ptrFromInt(top - executor.TRAP_STACK_USABLE_BYTES);
    var hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (0..executor.TRAP_STACK_USABLE_BYTES) |offset| hash = (hash ^ bytes[offset]) *% 0x100_0000_01b3;
    return hash;
}

fn verifyNeighbors() void {
    for (&neighbors, 0..) |*expected, cpu| {
        const actual = native_entry.stateForCpu(@intCast(cpu)).*;
        const top = executor.preparedKernelStackForCpu(@intCast(cpu)) orelse proof.fail("Mapping xstate neighbor trap");
        if (!std.mem.eql(u8, std.mem.asBytes(expected), std.mem.asBytes(&actual)) or actual.native_entry_modes != 0 or
            stackHash(top) != stack_hashes[cpu]) proof.fail("Mapping xstate neighbor mutation");
    }
}

fn paintStorage(storage: *xstate.Storage) void {
    const begin = @intFromPtr(storage.state()) - @intFromPtr(&storage.bytes);
    @memset(storage.bytes[0..begin], 0xa5);
    @memset(storage.bytes[begin + @sizeOf(xstate.State) ..], 0xa5);
}

fn storageIntact(storage: *xstate.Storage) bool {
    const begin = @intFromPtr(storage.state()) - @intFromPtr(&storage.bytes);
    for (storage.bytes[0..begin]) |byte| if (byte != 0xa5) return false;
    for (storage.bytes[begin + @sizeOf(xstate.State) ..]) |byte| if (byte != 0xa5) return false;
    return storage.state().pkru == 0 and storage.state().reserved == 0;
}

fn imageAuthority(state: *align(64) xstate.State) bool {
    const start = @intFromPtr(state);
    const physical = address.directMappedPhysicalAddress(start, address.direct_map_capacity) orelse return false;
    if (paging.mappedRamSpan(physical, @sizeOf(xstate.State)) != start) return false;
    var page = start & ~@as(usize, 4095);
    while (page < start + @sizeOf(xstate.State)) : (page += 4096) {
        const permissions = paging.currentPagePermissions(page) orelse return false;
        if (!permissions.writable or permissions.executable or permissions.user) return false;
    }
    return true;
}

pub fn run(runtime: *task_runtime.Runtime, trap_top: usize, physical_cr3: usize) void {
    if (cpu_identity.currentIndex() != 0 or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or
        runtime.execution.hasLeases() or borrowCount(runtime) != 0 or transport.global.hasOutstandingForIssuer(&runtime.execution))
        proof.fail("Mapping xstate BSP ownership");
    wait(&owner_ready, 1);
    const bsp_cr3 = x86.readCr3();
    if (bsp_cr3 & x86.CR3_ADDRESS_MASK != physical_cr3 or executor.preparedKernelStackForCpu(OWNER) != trap_top)
        proof.fail("Mapping xstate BSP geometry");
    const anchor = table_backing.alloc(executor.Executor) orelse proof.fail("Mapping xstate anchor allocation");
    anchor.* = .{};
    const source = table_backing.alloc(executor.Executor) orelse proof.fail("Mapping xstate source allocation");
    source.* = .{};
    const scheduler = table_backing.alloc(scheduler_module.Scheduler) orelse proof.fail("Mapping xstate Scheduler allocation");
    scheduler.initializeAllocated(anchor);
    if (!scheduler_module.ArchitectureProof.bindDomain(scheduler, runtime) or !source.claimRuntimeBinding(scheduler, runtime) or
        !source.claimMappingRegistration(OWNER, scheduler, runtime)) proof.fail("Mapping xstate domain binding");
    var tasks: [2]*task_runtime.TaskRecord = undefined;
    var handles: [2]executor.MappingHandle = undefined;
    for (0..2) |index| {
        const task = runtime.createTask(.{
            .owner = .{ .kind = .app, .serial = 211 + index },
            .component_class = .app_component,
            .budget = .{ .cpu_time_ticks = 100, .memory_bytes = 4096, .endpoint_slots = 0, .shared_memory_bytes = 0 },
            .initial_component = .{ .label = "mapping-xstate", .entry = "mapping-xstate" },
            .local_only = true,
        }) catch proof.fail("Mapping xstate task creation");
        tasks[index] = task;
        task_ids[index] = task.id;
        contexts[index] = .{ .rax = 0x1122_3344_5566_7788 + index, .rbx = 0x8877_6655_4433_2211 + index, .instruction_pointer = 0x4000_8000 + index * 4096, .stack_pointer = 0x7fff_f000 - index * 4096, .flags = 0x202 };
        const before = paging.frameStats().allocated;
        const space = paging.createUserAddressSpace() catch proof.fail("Mapping xstate private root");
        if (paging.frameStats().allocated != before + 1 or !source.installPreparedExecutionMappingForArchitectureProof(task, space, contexts[index], &handles[index]))
            proof.fail("Mapping xstate root admission");
        roots[index] = space.switch_cr3 & x86.CR3_ADDRESS_MASK;
        const mapping = &source.mappings.?.getByHandle(handles[index]).?.mapping;
        storages[index] = mapping.owned_xstate orelse proof.fail("Mapping xstate private allocation");
        states[index] = storages[index].state();
        if (!imageAuthority(states[index])) proof.fail("Mapping xstate WB image authority");
        paintStorage(storages[index]);
    }
    if (roots[0] == roots[1] or @intFromPtr(states[0]) < @intFromPtr(states[1]) + @sizeOf(xstate.State) and
        @intFromPtr(states[1]) < @intFromPtr(states[0]) + @sizeOf(xstate.State)) proof.fail("Mapping xstate distinct backing");
    for (&seeds, 0..) |*seed, index| model.initialize(seed, index);
    model.initialize(&poison, 3);
    for (&results) |*result| model.initializeResult(result);
    for (&neighbors, 0..) |*snapshot, cpu| {
        snapshot.* = native_entry.stateForCpu(@intCast(cpu)).*;
        const top = executor.preparedKernelStackForCpu(@intCast(cpu)) orelse proof.fail("Mapping xstate trap snapshot");
        stack_hashes[cpu] = stackHash(top);
        if (snapshot.native_entry_modes != 0) proof.fail("Mapping xstate native entry flags");
    }
    const admitted = paging.frameStats().allocated;
    var previous_epoch: u64 = 0;
    for (0..EPOCHS) |index| {
        const selected = index % 2;
        const other = selected ^ 1;
        neighbor_state = states[other].*;
        const ticket = runtime.reserveExecution(tasks[selected], OWNER) catch proof.fail("Mapping xstate lease reservation");
        if (ticket.epoch <= previous_epoch) proof.fail("Mapping xstate epoch reuse");
        previous_epoch = ticket.epoch;
        var command: executor.ArchitecturePreparedCommand = undefined;
        var key: transport.Key = undefined;
        if (!source.bindPreparedExecutionForArchitectureProof(tasks[selected], handles[selected], ticket, &command) or
            !source.publishPreparedExecutionForArchitectureProof(&command, &key)) proof.fail("Mapping xstate queue publication");
        @atomicStore(u32, &phase, @intCast(index + 1), .release);
        wait(&returned_phase, @intCast(index + 1));
        if (!owner_ran or @atomicLoad(u32, &callback_count, .acquire) != index + 1 or
            (runtime.execution.phase(ticket) catch proof.fail("Mapping xstate returned phase")) != .returned or
            source.active_task_id != 0 or source.active_mapping != null or source.active_dispatch_lease != null or
            borrowCount(runtime) != 1 or source.materializedCount() != 2 or paging.frameStats().allocated != admitted)
            proof.fail("Mapping xstate returned pin");
        var receipt: ownership.ReturnRecord = undefined;
        runtime.execution.consumePreparedReturnInto(ticket, &receipt) catch proof.fail("Mapping xstate acquired receipt");
        if (!std.meta.eql(receipt, ownership.ReturnRecord{ .outcome = .yielded, .ui_revision = index + 1 }))
            proof.fail("Mapping xstate exact return scalar");
        if (index == 2) {
            if (runtime.collectExecution(ticket)) |_| proof.fail("Mapping xstate collected before completion") else |err| {
                if (err != error.Busy) proof.fail("Mapping xstate retained collection error");
            }
            if (executor.releaseRegisteredDomain(scheduler, runtime) or source.materializedCount() != 2 or
                borrowCount(runtime) != 1 or paging.frameStats().allocated != admitted)
                proof.fail("Mapping xstate retained domain backing");
        }
        @atomicStore(u32, &release_phase, @intCast(index + 1), .release);
        wait(&completed_phase, @intCast(index + 1));
        var completion: transport.Completion = undefined;
        transport.global.completionInto(key, &completion) catch proof.fail("Mapping xstate static completion");
        if (completion != .owner_returned) proof.fail("Mapping xstate unstarted completion");
        runtime.collectExecution(ticket) catch proof.fail("Mapping xstate acknowledged collection");
        if (borrowCount(runtime) != 0 or runtime.execution.hasLeases() or transport.global.hasOutstandingForIssuer(&runtime.execution) or
            source.materializedCount() != 2 or paging.frameStats().allocated != admitted or
            !storageIntact(storages[0]) or !storageIntact(storages[1]) or !model.compactedIntact(states[selected]) or
            !std.mem.eql(u8, std.mem.asBytes(&neighbor_state), std.mem.asBytes(states[other])))
            proof.fail("Mapping xstate persistent owner backing");
        // The real yield handler captures this exact resumed context in its
        // own Mapping; the other Mapping's context remains independent.
        contexts[selected].rax = 1;
        contexts[selected].rdx = index + 1;
        contexts[selected].rsi = 0;
        contexts[selected].instruction_pointer += 4;
        verifyNeighbors();
        switch (index) {
            0 => pass("MAPPING_A_SEED"),
            1 => pass("MAPPING_B_SEED"),
            2 => pass("MAPPING_A_RESTORE"),
            3 => pass("MAPPING_B_UPDATE"),
            else => unreachable,
        }
    }
    wait(&owner_ready, 2);
    verifyNeighbors();
    if (@atomicLoad(u32, &callback_count, .acquire) != EPOCHS or source.materializedCount() != 2 or
        paging.frameStats().allocated != admitted or x86.readCr3() != bsp_cr3 or x86.interruptsEnabled())
        proof.fail("Mapping xstate final execution ownership");
    pass("OWNERSHIP");
    for (tasks) |task| {
        const asid = task.address_space_id;
        if (!(runtime.terminateTask(task.id, 920) catch proof.fail("Mapping xstate termination")) or
            runtime.findAddressSpaceConst(asid) != null or task.execution_component_count != 0)
            proof.fail("Mapping xstate exact retirement callback");
    }
    if (!executor.collectRegisteredRetiredMappings(scheduler, runtime) or source.materializedCount() != 0 or
        paging.frameStats().allocated != admitted - 2) proof.fail("Mapping xstate exact two-root recovery");
    scheduler.deinit();
    for ([_]*executor.Executor{ anchor, source }) |value| {
        if (value.registration_cpu != null or value.bound_runtime != null or value.binding_owner != null or value.materializedCount() != 0)
            proof.fail("Mapping xstate drained registration");
        table_backing.free(executor.Executor, value);
    }
    table_backing.free(scheduler_module.Scheduler, scheduler);
    verifyNeighbors();
    if (borrowCount(runtime) != 0 or runtime.execution.hasLeases() or transport.global.hasOutstandingForIssuer(&runtime.execution) or
        paging.frameStats().allocated != admitted - 2 or !paging.kernelAddressSpaceActive() or x86.readCr3() != bsp_cr3)
        proof.fail("Mapping xstate cleanup ownership");
    pass("RETIREMENT");
    @atomicStore(u32, &phase, DONE, .release);
    console.print("ZIGOS:ARCH:X86_64:MAPPING_XSTATE:PASS\n");
}

fn callback(context: *anyopaque, entry: *const executor.ArchitecturePreparedEntry) ownership.ReturnRecord {
    if (context != @as(*anyopaque, @ptrCast(&owner_phase)) or owner_phase == 0 or owner_phase > EPOCHS)
        proof.fail("Mapping xstate callback phase");
    const index = owner_phase - 1;
    const selected = index % 2;
    const other = selected ^ 1;
    if (cpu_identity.currentIndex() != OWNER or x86.interruptsEnabled() or paging.kernelAddressSpaceActive() or
        entry.task_id != task_ids[selected] or entry.physical_root != roots[selected] or
        x86.readCr3() & x86.CR3_ADDRESS_MASK != roots[selected] or native_entry.current().native_entry_modes != 0 or
        native_entry.current().kernel_stack_top != entry.trap_stack_top or entry.xstate_address != @intFromPtr(states[selected]) or
        !std.meta.eql(entry.user_context.*, contexts[selected]) or !imageAuthority(states[selected]) or
        !std.mem.eql(u8, std.mem.asBytes(&neighbor_state), std.mem.asBytes(states[other])))
        proof.fail("Mapping xstate actual owner receipt");
    const seed = if (index == 3) &seeds[2] else &seeds[selected];
    zigos_mapping_xstate_roundtrip(states[selected], seed, &poison, &results[index], index);
    if (!model.restoredIntact(seed, &results[index].restored) or (index < 2 and !model.initialIntact(&results[index].initial)) or
        !model.compactedIntact(states[selected]) or !storageIntact(storages[0]) or !storageIntact(storages[1]) or
        !std.mem.eql(u8, std.mem.asBytes(&neighbor_state), std.mem.asBytes(states[other])))
        proof.fail("Mapping xstate hardware roundtrip oracle");
    _ = @atomicRmw(u32, &callback_count, .Add, 1, .monotonic);
    return .{ .outcome = .yielded, .ui_revision = owner_phase };
}

fn afterReturn(context: *anyopaque, ran: bool) void {
    // After execution ACK the owner uses only permanent scalar synchronization.
    // It never rereads a command, issuer, Runtime, Mapping or image allocation.
    if (context != @as(*anyopaque, @ptrCast(&owner_phase))) proof.fail("Mapping xstate completion hook");
    owner_ran = ran;
    const current_phase = owner_phase;
    @atomicStore(u32, &returned_phase, current_phase, .release);
    wait(&release_phase, current_phase);
}

pub fn hold(index: u8, trap_top: usize, ordinary_bottom: usize, ordinary_top: usize) void {
    if (index != OWNER) return;
    if (rawCapabilities().unsupported() != null) proof.fail("Mapping xstate selected capability mismatch");
    const saved_entry = native_entry.current().*;
    const saved_cr0 = x86.readCr0();
    const saved_cr4 = x86.readCr4();
    const saved_cr3 = x86.readCr3();
    if (cpu_identity.currentIndex() != OWNER or x86.interruptsEnabled() or !paging.kernelAddressSpaceActive() or
        saved_entry.native_entry_modes != 0 or saved_cr4 & (x86.CR4_OSXSAVE | x86.CR4_PKE | x86.CR4_FRED) != x86.CR4_OSXSAVE or
        saved_cr0 & (x86.CR0_EM | x86.CR0_TS) != 0 or x86.readXcr0() != 7 or
        executor.preparedKernelStackForCpu(OWNER) != trap_top) proof.fail("Mapping xstate selected controls");
    // Raw XSAVES admission above dominates the first XSS access. No native
    // entry mode or READY bit is fabricated for the generic production macros.
    const saved_xss = x86.readMsr(x86.IA32_XSS_MSR);
    x86.writeMsr(x86.IA32_XSS_MSR, 0);
    if (x86.readMsr(x86.IA32_XSS_MSR) != 0 or cpuid(0xD, 0).ebx != xstate.image_bytes or cpuid(0xD, 1).ebx != xstate.image_bytes)
        proof.fail("Mapping xstate enabled layout");
    @atomicStore(u32, &owner_ready, 1, .release);
    for (1..DONE) |current_phase| {
        wait(&phase, @intCast(current_phase));
        owner_phase = @intCast(current_phase);
        const rsp = x86.stackPointer();
        if (rsp <= ordinary_bottom or rsp >= ordinary_top) proof.fail("Mapping xstate ordinary stack");
        _ = native_entry.initializeCpu(OWNER, trap_top);
        if (!executor.runQueuedPreparedExecutionForArchitectureProof(callback, &owner_phase, &saved_entry, null, afterReturn, &owner_phase))
            proof.fail("Mapping xstate owner command rejected");
        // Only hardware controls and permanent GS/scalars remain after ACK.
        const restored_entry = native_entry.current().*;
        if (x86.readCr0() != saved_cr0 or x86.readCr4() != saved_cr4 or x86.readCr3() != saved_cr3 or
            x86.readXcr0() != 7 or x86.readMsr(x86.IA32_XSS_MSR) != 0 or x86.interruptsEnabled() or
            !std.mem.eql(u8, std.mem.asBytes(&restored_entry), std.mem.asBytes(&saved_entry)))
            proof.fail("Mapping xstate caller controls restore");
        @atomicStore(u32, &completed_phase, @intCast(current_phase), .release);
    }
    x86.writeMsr(x86.IA32_XSS_MSR, saved_xss);
    if (x86.readMsr(x86.IA32_XSS_MSR) != saved_xss) proof.fail("Mapping xstate XSS restore");
    @atomicStore(u32, &owner_ready, 2, .release);
    wait(&phase, DONE);
}
