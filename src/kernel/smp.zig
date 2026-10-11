const builtin = @import("builtin");
const std = @import("std");
const cpu_identity = @import("cpu_identity.zig");
const config = @import("config.zig");
const cpu_policy = @import("boot/cpu_policy.zig");
const tlb_request = @import("smp/tlb_request.zig");
const cache_rendezvous = @import("smp/cache_rendezvous.zig");
const apic = @import("platform/apic.zig");
const x2apic = @import("interrupts/x2apic.zig");
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../arch/x86.zig")
else
    struct {
        pub fn readCr3() usize {
            return 0;
        }
        pub fn writeCr3(_: usize) void {}
        pub fn processContextIdentifiersEnabled() bool {
            return false;
        }
        pub fn invalidatePcid(_: u16) void {}
        pub fn invalidateAllTranslations() void {}
        pub fn writeBackInvalidateCaches() void {}
        pub fn interruptsEnabled() bool {
            return false;
        }
        pub fn cli() void {}
        pub fn sti() void {}
        pub fn stiHlt() void {}
    };
const tsc_clock = if (builtin.target.os.tag == .freestanding)
    @import("timer/tsc_clock.zig")
else
    struct {
        pub const Deadline = struct {
            pub fn expired(_: @This()) bool {
                return true;
            }
        };
        pub fn afterMilliseconds(_: u64) Deadline {
            return .{};
        }
    };
const spin = @import("utils/spin.zig");
const common = if (builtin.target.os.tag == .freestanding)
    @import("boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
        pub fn printCpuCount(_: u32) void {}
    };
const boot_markers = @import("boot/markers.zig");
const console = if (builtin.target.os.tag == .freestanding)
    @import("utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

pub const MAX_CPUS = cpu_identity.MAX_CPUS;

comptime {
    if (MAX_CPUS != tlb_request.CAPACITY)
        @compileError("CPU topology and TLB participant capacity must match");
    const owned_vectors = [_]u8{ TLB_IPI_VECTOR, EXECUTION_STOP_IPI_VECTOR, SYSCALL_REQUEST_IPI_VECTOR, SYSCALL_COMPLETION_IPI_VECTOR, PREPARED_EXECUTION_IPI_VECTOR };
    for (owned_vectors, 0..) |vector, index| {
        for (owned_vectors[0..index]) |prior| {
            if (vector == prior) @compileError("architectural IPI vectors must be distinct");
        }
    }
}

pub const TLB_IPI_VECTOR: u8 = 0x70;
pub const EXECUTION_STOP_IPI_VECTOR: u8 = 0x71;
pub const SYSCALL_REQUEST_IPI_VECTOR: u8 = 0x72;
pub const SYSCALL_COMPLETION_IPI_VECTOR: u8 = 0x73;
pub const PREPARED_EXECUTION_IPI_VECTOR: u8 = 0x74;
pub const AP_STACK_BYTES: usize = 16 * 1024;
pub const STARTS_APPLICATION_PROCESSORS = true;
pub const SINGLE_RUNTIME_OWNER = true;
pub const SHOOTS_DOWN_REMOTE_TLB = true;
pub const PINS_DEVICE_IRQS_TO_BSP = true;
pub const IDLES_PER_CPU = true;
pub const SIPI_PHYSICAL_LIMIT: u32 = 1024 * 1024;

pub const Cpu = struct {
    apic_id: u32 = 0,
    online: bool = false,
    kernel_stack_top: usize = 0,
};

const bringup = if (builtin.target.os.tag == .freestanding)
    @import("smp_bringup.zig")
else
    struct {
        pub fn start(_: *[MAX_CPUS]Cpu, _: *u8, _: *u8, _: cpu_policy.AdmissionPolicy) void {}
    };

var cpus: [MAX_CPUS]Cpu = @as([MAX_CPUS]Cpu, @splat(.{}));
var cpu_count: u8 = 1;
var online_count: u8 = 1;
var bsp_cpu_index: u8 = 0;
var tlb_requests = tlb_request.Coordinator.init(0) catch unreachable;
var cache_transitions = cache_rendezvous.Coordinator.init(0) catch unreachable;
var cache_transition_generation: u64 = 0;
var cache_transition_restore_interrupts = false;
var initialized = false;

pub fn init(madt: []const u8, admission_policy: cpu_policy.AdmissionPolicy) void {
    const madt_table = madt;
    if (!config.shouldInitSmp()) {
        common.printBootMarker(boot_markers.smp_ready);
        return;
    }

    const bsp_apic_id: u32 = if (builtin.target.os.tag == .freestanding) x2apic.localId() else 0;
    cpus[0] = .{ .apic_id = bsp_apic_id, .online = true };
    cpu_count = 1;
    @atomicStore(u8, &online_count, 1, .release);
    bsp_cpu_index = 0;

    if (builtin.target.os.tag == .freestanding) {
        const admission = inventoryFromMadt(bsp_apic_id, madt_table) catch |err| {
            console.print("Invalid SMP MADT topology: ");
            console.print(@errorName(err));
            console.print("\n");
            @panic("SMP topology admission failed");
        };
        if (admission.capacity_exceeded) {
            console.print("SMP configured CPU capacity exceeded; admitted subset only\n");
        }
        bringup.start(&cpus, &cpu_count, &online_count, admission_policy);
    }

    initialized = true;
    console.print("SMP online CPUs: ");
    common.printCpuCount(onlineCpuCount());
    console.print("\n");
    common.printBootMarker(boot_markers.smp_ready);
}

pub fn onlineCpuCount() u8 {
    return @max(@atomicLoad(u8, &online_count, .acquire), 1);
}

pub fn currentCpuIndex() u8 {
    return cpu_identity.currentIndex();
}

// The shared executor, kernel port, and service tables belong to the BSP.
// APs service architectural interrupts; they do not dispatch runtime work.
pub fn runtimeOwnerCpu() u8 {
    return bsp_cpu_index;
}

pub fn isRuntimeOwner() bool {
    return currentCpuIndex() == runtimeOwnerCpu();
}

pub fn irqDestinationId() u32 {
    if (!initialized and builtin.target.os.tag == .freestanding) return x2apic.localId();
    return cpus[runtimeOwnerCpu()].apic_id;
}

pub fn setOnlineCpuCountForTest(count: u8) u8 {
    if (!builtin.is_test) @compileError("CPU topology override is test-only");
    std.debug.assert(count > 0 and count <= MAX_CPUS);
    return @atomicRmw(u8, &online_count, .Xchg, count, .acq_rel);
}

pub fn idle() void {
    if (builtin.target.os.tag != .freestanding) return;
    x86.stiHlt();
}

// This is only a prompt: the lease's selected owner must separately publish
// its returned acknowledgement before BSP collection can retire resources.
pub fn notifyExecutionStop(cpu: u8) bool {
    if (!initialized or !isRuntimeOwner() or cpu >= MAX_CPUS or cpu >= cpu_count or cpu == currentCpuIndex()) return false;
    if (!@atomicLoad(bool, &cpus[cpu].online, .acquire)) return false;
    x2apic.sendIpi(.{ .destination = cpus[cpu].apic_id, .vector = EXECUTION_STOP_IPI_VECTOR, .delivery = .fixed });
    return true;
}

// Publication owns the command; this doorbell only prompts its selected CPU.
// Neither delivery nor EOI claims execution or acknowledges owner completion.
pub fn notifyPreparedExecution(cpu: u8) bool {
    if (!initialized or !isRuntimeOwner() or cpu >= MAX_CPUS or cpu >= cpu_count or cpu == currentCpuIndex()) return false;
    if (!@atomicLoad(bool, &cpus[cpu].online, .acquire)) return false;
    x2apic.sendIpi(.{ .destination = cpus[cpu].apic_id, .vector = PREPARED_EXECUTION_IPI_VECTOR, .delivery = .fixed });
    return true;
}

// Mailbox publication owns the request; the vector only wakes the BSP's
// deferred service loop. An AP must never enter shared Runtime work here.
pub fn notifySyscallRequest() bool {
    const cpu = currentCpuIndex();
    if (!initialized or isRuntimeOwner() or cpu >= MAX_CPUS or cpu >= cpu_count) return false;
    if (!@atomicLoad(bool, &cpus[cpu].online, .acquire) or
        !@atomicLoad(bool, &cpus[0].online, .acquire)) return false;
    x2apic.sendIpi(.{ .destination = cpus[0].apic_id, .vector = SYSCALL_REQUEST_IPI_VECTOR, .delivery = .fixed });
    return true;
}

// Completion still needs exact issuer/epoch/sequence validation and owner
// consumption. Neither this IPI nor its EOI acknowledges execution return.
pub fn notifySyscallCompletion(cpu: u8) bool {
    if (!initialized or !isRuntimeOwner() or cpu >= MAX_CPUS or cpu >= cpu_count or cpu == currentCpuIndex()) return false;
    if (!@atomicLoad(bool, &cpus[cpu].online, .acquire)) return false;
    x2apic.sendIpi(.{ .destination = cpus[cpu].apic_id, .vector = SYSCALL_COMPLETION_IPI_VECTOR, .delivery = .fixed });
    return true;
}

pub fn shootdownPcid(pcid: u16) void {
    shootdown(.{ .pcid = pcid });
}

// Paging completes its local VA invalidations before this remote barrier.
// Full invalidation on each AP includes global kernel leaves in every PCID.
pub fn shootdownKernel() void {
    shootdown(.{ .kernel = {} });
}

fn shootdown(target: tlb_request.Target) void {
    if (builtin.target.os.tag != .freestanding) return;
    if (!isRuntimeOwner()) @panic("remote TLB shootdown requires the BSP runtime owner");
    if (cache_transition_generation != 0) @call(.never_inline, cacheTransitionFailure, .{.nested_tlb});
    // Disallow interrupt reentry while publishing or retiring a request. AP
    // handlers only invalidate/EOI/ack; no paging or allocator lock is needed.
    const restore_interrupts = x86.interruptsEnabled();
    x86.cli();
    defer if (restore_interrupts) x86.sti();
    const self = currentCpuIndex();
    const participants = capturedParticipants(self);
    if (@popCount(participants) <= 1) return;
    const request = tlb_requests.begin(self, target, participants) catch
        @panic("invalid or concurrent remote TLB request");
    sendParticipantIpis(self, participants);

    const deadline = tsc_clock.afterMilliseconds(100);
    // The immutable participant snapshot cannot grow during this wait, and a
    // duplicate or delayed acknowledgement cannot complete another request.
    while (!tlb_requests.complete(request.generation)) {
        if (deadline.expired()) {
            tlb_requests.fail(self) catch unreachable;
            @panic("remote TLB shootdown timed out");
        }
        spin.hint();
    }
    tlb_requests.finish(self, request.generation) catch unreachable;
}

inline fn capturedParticipants(self: u8) tlb_request.CpuMask {
    var participants = tlb_request.cpuBit(self) orelse @call(.never_inline, cacheTransitionFailure, .{.invalid_owner_cpu});
    var index: u8 = 0;
    while (index < cpu_count) : (index += 1) {
        if (index != self and @atomicLoad(bool, &cpus[index].online, .acquire))
            participants |= tlb_request.cpuBit(index).?;
    }
    return participants;
}

inline fn sendParticipantIpis(self: u8, participants: tlb_request.CpuMask) void {
    var index: u8 = 0;
    while (index < cpu_count) : (index += 1) {
        if (index == self or participants & tlb_request.cpuBit(index).? == 0) continue;
        x2apic.sendIpi(.{ .destination = cpus[index].apic_id, .vector = TLB_IPI_VECTOR, .delivery = .fixed });
    }
}

const CacheTransitionFailure = enum {
    nested_tlb,
    invalid_owner_cpu,
    owner_or_reentry,
    begin,
    flush_context,
    park_barrier,
    local_flush_stamp,
    release_context,
    retirement_barrier,
    timeout,
    park_stamp,
    remote_flush_stamp,
    release_stamp,
    phase,
};

// Compile-time concatenation retains an addressable byte blob. Returning a
// locally filled array inside an anonymous packed table loses its base address
// with the pinned compiler, so offsets and message storage are independent.
const cache_failure_messages = [_][]const u8{
    "TLB request inside a cache transition",
    "invalid transition owner CPU",
    "invalid device cache transition owner or reentry",
    "invalid or concurrent device cache transition",
    "device cache flush outside held transition",
    "device aliases detached before all CPUs parked",
    "invalid local device cache flush stamp",
    "device cache release outside held transition",
    "device mapping published before cache retirement",
    "device cache rendezvous timed out",
    "invalid cache park stamp",
    "invalid remote cache flush stamp",
    "cache participant released without retirement",
    "invalid live cache rendezvous phase",
};

const cache_failure_message_bytes: []const u8 = blk: {
    if (cache_failure_messages.len != @typeInfo(CacheTransitionFailure).@"enum".field_names.len)
        @compileError("cache transition failure messages must cover every stage");
    var bytes: []const u8 = "";
    for (cache_failure_messages) |message| bytes = bytes ++ message;
    break :blk bytes;
};

const cache_failure_message_offsets = blk: {
    var offsets: [cache_failure_messages.len + 1]u16 = undefined;
    var cursor: usize = 0;
    for (cache_failure_messages, 0..) |message, index| {
        offsets[index] = @intCast(cursor);
        cursor += message.len;
    }
    offsets[cache_failure_messages.len] = @intCast(cursor);
    break :blk offsets;
};

fn cacheTransitionFailureMessage(stage: CacheTransitionFailure) []const u8 {
    const index: usize = @backingInt(stage);
    return cache_failure_message_bytes[cache_failure_message_offsets[index]..cache_failure_message_offsets[index + 1]];
}

fn cacheTransitionFailure(stage: CacheTransitionFailure) noreturn {
    @branchHint(.cold);
    @panic(cacheTransitionFailureMessage(stage));
}

test "cache transition diagnostics retain real bytes for every runtime stage" {
    var index: usize = 0;
    while (index < cache_failure_messages.len) : (index += 1) {
        std.mem.doNotOptimizeAway(&index);
        const stage: CacheTransitionFailure = @fromBackingInt(@intCast(index));
        const message = @call(.never_inline, cacheTransitionFailureMessage, .{stage});
        try std.testing.expectEqualStrings(cache_failure_messages[index], message);
        try std.testing.expectEqual(@intFromPtr(cache_failure_message_bytes.ptr) + cache_failure_message_offsets[index], @intFromPtr(message.ptr));
    }
    try std.testing.expectEqual(cache_failure_message_bytes.len, cache_failure_message_offsets[cache_failure_messages.len]);
}

// Paging preflights authority, collision checks and every required table before
// begin. No allocation, paging-lock acquisition or fallible work is allowed
// between these hooks. Only the BSP mutates kernel leaves; no CPU hotplug.
pub fn beginDeviceAliasTransition() void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    if (!isRuntimeOwner() or cache_transition_generation != 0)
        @call(.never_inline, cacheTransitionFailure, .{.owner_or_reentry});
    cache_transition_restore_interrupts = x86.interruptsEnabled();
    x86.cli();
    const self = currentCpuIndex();
    const participants = capturedParticipants(self);
    cache_transition_generation = cache_transitions.begin(self, participants) catch
        @call(.never_inline, cacheTransitionFailure, .{.begin});
    sendParticipantIpis(self, participants);
    waitForCachePhase(.parking);
}

// The former WB direct leaves and replaced UC destination leaves are absent.
// Every AP remains held while all caches and global/PCID translations retire.
// PAT/MTRRs and CR0 cache controls remain the admitted immutable configuration.
pub fn flushDeviceAliasTransition() void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    if (!isRuntimeOwner() or cache_transition_generation == 0 or x86.interruptsEnabled())
        @call(.never_inline, cacheTransitionFailure, .{.flush_context});
    const self = currentCpuIndex();
    cache_transitions.startFlush(self, cache_transition_generation) catch
        @call(.never_inline, cacheTransitionFailure, .{.park_barrier});
    x86.invalidateAllTranslations();
    x86.writeBackInvalidateCaches();
    if (!cache_transitions.recordFlush(self, cache_transition_generation))
        @call(.never_inline, cacheTransitionFailure, .{.local_flush_stamp});
    waitForCachePhase(.flushing);
}

// Called only after all new strict-UC or admitted firmware-WB leaves are
// published. The release store orders publication before AP handler return.
pub fn endDeviceAliasTransition() void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    if (!isRuntimeOwner() or cache_transition_generation == 0 or x86.interruptsEnabled())
        @call(.never_inline, cacheTransitionFailure, .{.release_context});
    const self = currentCpuIndex();
    cache_transitions.release(self, cache_transition_generation) catch
        @call(.never_inline, cacheTransitionFailure, .{.retirement_barrier});
    waitForCachePhase(.releasing);
    cache_transitions.finish(self, cache_transition_generation) catch unreachable;
    cache_transition_generation = 0;
    if (cache_transition_restore_interrupts) x86.sti();
}

inline fn waitForCachePhase(comptime phase: cache_rendezvous.Phase) void {
    const deadline = tsc_clock.afterMilliseconds(100);
    while (!switch (phase) {
        .parking => cache_transitions.parked(cache_transition_generation),
        .flushing => cache_transitions.flushed(cache_transition_generation),
        .releasing => cache_transitions.released(cache_transition_generation),
        else => @compileError("invalid cache barrier phase"),
    }) {
        if (deadline.expired()) {
            cache_transitions.fail(currentCpuIndex()) catch unreachable;
            @call(.never_inline, cacheTransitionFailure, .{.timeout});
        }
        spin.hint();
    }
}

pub fn handleTlbIpi() void {
    const cpu = currentCpuIndex();
    if (cache_transitions.pending(cpu)) |generation| {
        x2apic.acknowledge();
        if (!cache_transitions.park(cpu, generation)) @call(.never_inline, cacheTransitionFailure, .{.park_stamp});
        var flushed = false;
        while (true) {
            switch (cache_transitions.phaseFor(generation) orelse {
                // Failure cannot release a CPU into a partially changed map.
                x86.cli();
                while (true) spin.hint();
            }) {
                .parking => {},
                .flushing => if (!flushed) {
                    x86.invalidateAllTranslations();
                    x86.writeBackInvalidateCaches();
                    if (!cache_transitions.recordFlush(cpu, generation)) @call(.never_inline, cacheTransitionFailure, .{.remote_flush_stamp});
                    flushed = true;
                },
                .releasing => {
                    if (!flushed or !cache_transitions.recordRelease(cpu, generation))
                        @call(.never_inline, cacheTransitionFailure, .{.release_stamp});
                    return;
                },
                else => @call(.never_inline, cacheTransitionFailure, .{.phase}),
            }
            spin.hint();
        }
    }
    if (tlb_requests.pending(cpu)) |request| {
        switch (request.target) {
            .pcid => |pcid| {
                if (x86.processContextIdentifiersEnabled()) {
                    x86.invalidatePcid(pcid);
                } else {
                    x86.writeCr3(x86.readCr3());
                }
            },
            .kernel => x86.invalidateAllTranslations(),
        }
        x2apic.acknowledge();
        _ = tlb_requests.acknowledge(cpu, request.generation);
        return;
    }
    // An unrelated or coalesced stale vector carries no completion authority.
    x2apic.acknowledge();
}

const architecture_proof_enabled = if (@hasDecl(@import("root"), "ARCHITECTURE_SMP_PROOF"))
    @import("root").ARCHITECTURE_SMP_PROOF
else
    false;

pub const ArchitectureProof = if (architecture_proof_enabled) struct {
    pub fn bindTopology(apic_ids: []const u32) void {
        if (comptime builtin.target.os.tag != .freestanding)
            @compileError("architecture proof topology requires a freestanding proof image");
        if (initialized or apic_ids.len == 0 or apic_ids.len > MAX_CPUS or currentCpuIndex() != 0 or
            apic_ids[0] != x2apic.localId()) @panic("invalid architecture proof topology");
        for (apic_ids, 0..) |apic_id, logical| {
            for (apic_ids[0..logical]) |earlier| {
                if (earlier == apic_id) @panic("duplicate architecture proof CPU");
            }
            cpus[logical] = .{ .apic_id = apic_id, .online = true };
        }
        cpu_count = @intCast(apic_ids.len);
        @atomicStore(u8, &online_count, cpu_count, .release);
        bsp_cpu_index = 0;
        initialized = true;
    }
} else struct {};

pub fn setCurrentCpuIndexForTest(index: u8) void {
    cpu_identity.setIndexForTest(index);
}

const TopologyError = apic.Error || error{
    InvalidCpuCapacity,
    MissingBootstrapProcessor,
};

const TopologyAdmission = struct {
    count: u8,
    capacity_exceeded: bool,
};

fn inventoryFromMadt(bsp_apic_id: u32, table: []const u8) TopologyError!TopologyAdmission {
    const admission = try admitMadtProcessors(bsp_apic_id, table, &cpus);
    cpu_count = admission.count;
    return admission;
}

fn admitMadtProcessors(bsp_apic_id: u32, table: []const u8, admitted: []Cpu) TopologyError!TopologyAdmission {
    if (admitted.len == 0 or admitted.len > std.math.maxInt(u8)) return error.InvalidCpuCapacity;
    var processors = try apic.ProcessorIterator.init(table);
    // Validate the running BSP before publishing any topology. A malformed
    // table or missing enabled BSP cannot masquerade as a complete UP system.
    var bsp_scan = processors;
    var bsp_found = false;
    while (bsp_scan.next()) |processor| {
        if (processor.enabled and processor.apic_id == bsp_apic_id) {
            bsp_found = true;
            break;
        }
    }
    if (!bsp_found) return error.MissingBootstrapProcessor;

    admitted[0] = .{ .apic_id = bsp_apic_id, .online = true };
    var count: usize = 1;
    var capacity_exceeded = false;
    while (processors.next()) |processor| {
        if (!processor.enabled) continue;
        var duplicate = false;
        for (admitted[0..count]) |cpu| {
            if (cpu.apic_id == processor.apic_id) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        if (count == admitted.len) {
            // Retain the admitted unique set and still consume the validated
            // stream. This result explicitly describes a bounded subset.
            capacity_exceeded = true;
            continue;
        }
        admitted[count] = .{ .apic_id = processor.apic_id, .online = false };
        count += 1;
    }
    return .{ .count = @intCast(count), .capacity_exceeded = capacity_exceeded };
}

const MadtTestFixture = struct {
    storage: [apic.MADT_HEADER_LENGTH + 128 * 16]u8 = @splat(0),
    len: usize = apic.MADT_HEADER_LENGTH,

    fn init() MadtTestFixture {
        var fixture: MadtTestFixture = .{};
        @memcpy(fixture.storage[0..4], apic.MADT_SIGNATURE);
        fixture.storage[8] = 5;
        std.mem.writeInt(u32, fixture.storage[36..40], 0xFEE0_0000, .little);
        return fixture;
    }

    fn local(self: *MadtTestFixture, id: u8, enabled: bool) void {
        const entry = self.storage[self.len..][0..8];
        self.len += entry.len;
        entry[0] = 0;
        entry[1] = 8;
        entry[3] = id;
        std.mem.writeInt(u32, entry[4..8], @intFromBool(enabled), .little);
    }

    fn x2(self: *MadtTestFixture, id: u32, uid: u32, enabled: bool) void {
        const entry = self.storage[self.len..][0..16];
        self.len += entry.len;
        entry[0] = 9;
        entry[1] = 16;
        std.mem.writeInt(u32, entry[4..8], id, .little);
        std.mem.writeInt(u32, entry[8..12], @intFromBool(enabled), .little);
        std.mem.writeInt(u32, entry[12..16], uid, .little);
    }

    fn table(self: *MadtTestFixture) []const u8 {
        std.mem.writeInt(u32, self.storage[4..8], @intCast(self.len), .little);
        @import("utils/checksum.zig").finishSum8Prefix(&self.storage, 9, self.len);
        return self.storage[0..self.len];
    }
};

test "SMP topology admits sixteen sparse x2APIC IDs with the BSP at logical zero" {
    var fixture = MadtTestFixture.init();
    var ids: [16]u32 = undefined;
    for (&ids, 0..) |*id, index| {
        id.* = 0x1000 + @as(u32, @intCast(index)) * 13;
        fixture.x2(id.*, @intCast(index), true);
    }
    const bsp = ids[7];
    var admitted: [16]Cpu = undefined;
    const result = try admitMadtProcessors(bsp, fixture.table(), &admitted);
    try std.testing.expectEqual(@as(u8, 16), result.count);
    try std.testing.expect(!result.capacity_exceeded);
    try std.testing.expectEqual(bsp, admitted[0].apic_id);
    try std.testing.expect(admitted[0].online);
    var logical: usize = 1;
    for (ids) |id| {
        if (id == bsp) continue;
        try std.testing.expectEqual(id, admitted[logical].apic_id);
        try std.testing.expect(!admitted[logical].online);
        logical += 1;
    }
}

test "SMP topology ignores disabled records and deduplicates mixed APIC entries at capacity" {
    var fixture = MadtTestFixture.init();
    for (0..80) |index| fixture.x2(0x2000 + @as(u32, @intCast(index)), 1, false);
    fixture.local(42, false);
    fixture.local(7, true);
    fixture.x2(7, 0, true);
    fixture.local(17, false);
    fixture.x2(17, 2, true);
    fixture.local(42, true);
    fixture.x2(42, 0, true);
    for (0..20) |_| fixture.x2(17, 0, true);
    var admitted: [3]Cpu = undefined;
    const result = try admitMadtProcessors(42, fixture.table(), &admitted);
    try std.testing.expectEqual(@as(u8, 3), result.count);
    try std.testing.expect(!result.capacity_exceeded);
    try std.testing.expectEqual(@as(u32, 42), admitted[0].apic_id);
    try std.testing.expectEqual(@as(u32, 7), admitted[1].apic_id);
    try std.testing.expectEqual(@as(u32, 17), admitted[2].apic_id);
}

test "SMP topology retains its admitted subset and reports enabled CPU capacity overflow" {
    var fixture = MadtTestFixture.init();
    for (1..6) |id| fixture.x2(@intCast(id), 0, true);
    fixture.x2(9, 0, true);
    fixture.x2(1, 0, true);
    fixture.x2(2, 0, true);
    var admitted: [3]Cpu = undefined;
    const result = try admitMadtProcessors(9, fixture.table(), &admitted);
    try std.testing.expectEqual(@as(u8, 3), result.count);
    try std.testing.expect(result.capacity_exceeded);
    try std.testing.expectEqual(@as(u32, 9), admitted[0].apic_id);
    try std.testing.expectEqual(@as(u32, 1), admitted[1].apic_id);
    try std.testing.expectEqual(@as(u32, 2), admitted[2].apic_id);
}

test "SMP topology rejects a malformed tail before changing admitted CPUs" {
    var fixture = MadtTestFixture.init();
    for (0..16) |id| fixture.x2(@intCast(id), 0, true);
    fixture.storage[fixture.len] = 9;
    fixture.storage[fixture.len + 1] = 16;
    fixture.len += 2;
    const sentinel = Cpu{ .apic_id = 0xABCD, .kernel_stack_top = 0x1000 };
    var admitted: [4]Cpu = @splat(sentinel);
    const before = admitted;
    try std.testing.expectError(error.InvalidEntryLength, admitMadtProcessors(0, fixture.table(), &admitted));
    try std.testing.expectEqualDeep(before, admitted);
}

test "SMP topology requires an enabled BSP and a bounded output capacity" {
    var fixture = MadtTestFixture.init();
    fixture.local(7, true);
    fixture.x2(42, 1, false);
    var admitted: [3]Cpu = @splat(.{ .apic_id = 0xABCD });
    const before = admitted;
    try std.testing.expectError(error.MissingBootstrapProcessor, admitMadtProcessors(42, fixture.table(), &admitted));
    try std.testing.expectEqualDeep(before, admitted);
    try std.testing.expectError(error.InvalidCpuCapacity, admitMadtProcessors(7, fixture.table(), admitted[0..0]));
    try std.testing.expectError(error.TooSmall, admitMadtProcessors(7, &.{}, &admitted));
}

test "SMP routes runtime and device interrupts to one owner with multiple CPUs online" {
    const previous_count = setOnlineCpuCountForTest(4);
    defer _ = setOnlineCpuCountForTest(previous_count);
    const previous_initialized = initialized;
    defer initialized = previous_initialized;
    const previous_bsp = cpus[0];
    defer cpus[0] = previous_bsp;
    initialized = true;
    cpus[0].apic_id = 7;

    try std.testing.expectEqual(@as(u8, 4), onlineCpuCount());
    try std.testing.expectEqual(@as(u8, 0), runtimeOwnerCpu());
    try std.testing.expect(isRuntimeOwner());
    for (0..MAX_CPUS) |_| {
        try std.testing.expectEqual(@as(u32, 7), irqDestinationId());
    }
    try std.testing.expect(SINGLE_RUNTIME_OWNER);
    try std.testing.expect(PINS_DEVICE_IRQS_TO_BSP);
    try std.testing.expect(STARTS_APPLICATION_PROCESSORS);
    try std.testing.expect(SHOOTS_DOWN_REMOTE_TLB);
    try std.testing.expect(IDLES_PER_CPU);
    try std.testing.expectEqual(@as(u8, 0x70), TLB_IPI_VECTOR);
}

test "execution stop transport sends only admitted remote CPU fixed vectors" {
    const Trace = struct {
        var values: [MAX_CPUS * 2]u64 = undefined;
        var count: usize = 0;
        var invalid_msr = false;

        fn observe(msr: u32, value: u64) void {
            if (msr != x2apic.Testing.ICR_MSR) invalid_msr = true;
            values[count] = value;
            count += 1;
        }
    };
    const previous_cpu = currentCpuIndex();
    const previous_cpus = cpus;
    const previous_count = cpu_count;
    const previous_bsp = bsp_cpu_index;
    const previous_initialized = initialized;
    const previous_observer = x2apic.Testing.swapWriteObserver(Trace.observe);
    defer {
        _ = x2apic.Testing.swapWriteObserver(previous_observer);
        cpu_identity.setIndexForTest(previous_cpu);
        cpus = previous_cpus;
        cpu_count = previous_count;
        bsp_cpu_index = previous_bsp;
        initialized = previous_initialized;
    }
    Trace.count = 0;
    Trace.invalid_msr = false;
    cpu_identity.setIndexForTest(0);
    bsp_cpu_index = 0;
    initialized = true;
    cpu_count = MAX_CPUS;
    for (&cpus, 0..) |*cpu, index| {
        cpu.apic_id = 0x1234_0000 + @as(u32, @intCast(index));
        @atomicStore(bool, &cpu.online, true, .release);
    }
    try std.testing.expect(!notifyExecutionStop(0));
    try std.testing.expect(!notifyExecutionStop(MAX_CPUS));
    try std.testing.expect(!notifyExecutionStop(255));
    initialized = false;
    try std.testing.expect(!notifyExecutionStop(1));
    initialized = true;
    for (1..MAX_CPUS) |index| {
        const cpu: u8 = @intCast(MAX_CPUS - index);
        @atomicStore(bool, &cpus[cpu].online, false, .release);
        try std.testing.expect(!notifyExecutionStop(cpu));
        @atomicStore(bool, &cpus[cpu].online, true, .release);
        cpu_count = cpu;
        try std.testing.expect(!notifyExecutionStop(cpu));
        cpu_count = MAX_CPUS;
        cpu_identity.setIndexForTest(cpu);
        try std.testing.expect(!notifyExecutionStop(0));
        try std.testing.expect(!notifyExecutionStop(@intCast((cpu + 1) % MAX_CPUS)));
        cpu_identity.setIndexForTest(0);
        try std.testing.expectEqual(index - 1, Trace.count);
        try std.testing.expect(notifyExecutionStop(cpu));
        try std.testing.expectEqual(x2apic.icrValue(.{
            .destination = cpus[cpu].apic_id,
            .vector = EXECUTION_STOP_IPI_VECTOR,
            .delivery = .fixed,
        }), Trace.values[Trace.count - 1]);
    }
    try std.testing.expectEqual(@as(usize, MAX_CPUS - 1), Trace.count);
    try std.testing.expect(!Trace.invalid_msr);
    try std.testing.expectEqual(@as(u8, 0x71), EXECUTION_STOP_IPI_VECTOR);
}

test "prepared execution doorbell sends only admitted remote CPU fixed vectors" {
    const Trace = struct {
        var values: [MAX_CPUS * 2]u64 = undefined;
        var count: usize = 0;
        var invalid_msr = false;
        fn observe(msr: u32, value: u64) void {
            if (msr != x2apic.Testing.ICR_MSR or count >= values.len) {
                invalid_msr = true;
                return;
            }
            values[count] = value;
            count += 1;
        }
    };
    const previous_cpu = currentCpuIndex();
    const previous_cpus = cpus;
    const previous_count = cpu_count;
    const previous_bsp = bsp_cpu_index;
    const previous_initialized = initialized;
    const previous_observer = x2apic.Testing.swapWriteObserver(Trace.observe);
    defer {
        _ = x2apic.Testing.swapWriteObserver(previous_observer);
        cpu_identity.setIndexForTest(previous_cpu);
        cpus = previous_cpus;
        cpu_count = previous_count;
        bsp_cpu_index = previous_bsp;
        initialized = previous_initialized;
    }
    Trace.count = 0;
    Trace.invalid_msr = false;
    cpu_identity.setIndexForTest(0);
    bsp_cpu_index = 0;
    initialized = true;
    cpu_count = MAX_CPUS;
    for (&cpus, 0..) |*cpu, index| {
        cpu.apic_id = 0x9876_0000 + @as(u32, @intCast(index));
        @atomicStore(bool, &cpu.online, true, .release);
    }
    const topology_before = cpus;
    try std.testing.expect(!notifyPreparedExecution(0));
    try std.testing.expect(!notifyPreparedExecution(MAX_CPUS));
    try std.testing.expect(!notifyPreparedExecution(255));
    initialized = false;
    try std.testing.expect(!notifyPreparedExecution(1));
    initialized = true;
    for (1..MAX_CPUS) |index| {
        const cpu: u8 = @intCast(MAX_CPUS - index);
        @atomicStore(bool, &cpus[cpu].online, false, .release);
        try std.testing.expect(!notifyPreparedExecution(cpu));
        @atomicStore(bool, &cpus[cpu].online, true, .release);
        cpu_count = cpu;
        try std.testing.expect(!notifyPreparedExecution(cpu));
        cpu_count = MAX_CPUS;
        cpu_identity.setIndexForTest(cpu);
        try std.testing.expect(!notifyPreparedExecution(cpu));
        try std.testing.expect(!notifyPreparedExecution(0));
        try std.testing.expect(!notifyPreparedExecution(@intCast((cpu + 1) % MAX_CPUS)));
        cpu_identity.setIndexForTest(0);
        try std.testing.expectEqual(2 * (index - 1), Trace.count);
        // Duplicate prompts remain transport-only and need no queue/issuer.
        for (0..2) |_| {
            try std.testing.expect(notifyPreparedExecution(cpu));
            try std.testing.expectEqual(x2apic.icrValue(.{
                .destination = cpus[cpu].apic_id,
                .vector = PREPARED_EXECUTION_IPI_VECTOR,
                .delivery = .fixed,
            }), Trace.values[Trace.count - 1]);
        }
    }
    try std.testing.expectEqual(@as(usize, 2 * (MAX_CPUS - 1)), Trace.count);
    try std.testing.expect(!Trace.invalid_msr);
    try std.testing.expectEqualDeep(topology_before, cpus);
    try std.testing.expectEqual(@as(u8, 0x74), PREPARED_EXECUTION_IPI_VECTOR);
}

test "syscall doorbells follow admitted AP to BSP and BSP to AP ownership" {
    const Trace = struct {
        var values: [MAX_CPUS * 2]u64 = undefined;
        var count: usize = 0;
        var invalid_msr = false;
        fn observe(msr: u32, value: u64) void {
            if (msr != x2apic.Testing.ICR_MSR) invalid_msr = true;
            values[count] = value;
            count += 1;
        }
    };
    const previous_cpu = currentCpuIndex();
    const previous_cpus = cpus;
    const previous_count = cpu_count;
    const previous_bsp = bsp_cpu_index;
    const previous_initialized = initialized;
    const previous_observer = x2apic.Testing.swapWriteObserver(Trace.observe);
    defer {
        _ = x2apic.Testing.swapWriteObserver(previous_observer);
        cpu_identity.setIndexForTest(previous_cpu);
        cpus = previous_cpus;
        cpu_count = previous_count;
        bsp_cpu_index = previous_bsp;
        initialized = previous_initialized;
    }
    Trace.count = 0;
    Trace.invalid_msr = false;
    bsp_cpu_index = 0;
    initialized = true;
    cpu_count = MAX_CPUS;
    for (&cpus, 0..) |*cpu, index| {
        cpu.apic_id = 0xABCD_0000 + @as(u32, @intCast(index)) * 17;
        @atomicStore(bool, &cpu.online, true, .release);
    }
    cpu_identity.setIndexForTest(0);
    try std.testing.expect(!notifySyscallRequest());
    try std.testing.expect(!notifySyscallCompletion(0));
    try std.testing.expect(!notifySyscallCompletion(MAX_CPUS));
    try std.testing.expect(!notifySyscallCompletion(255));
    for (1..MAX_CPUS) |index| {
        const cpu: u8 = @intCast(index);
        cpu_identity.setIndexForTest(cpu);
        initialized = false;
        try std.testing.expect(!notifySyscallRequest());
        initialized = true;
        cpu_count = cpu;
        try std.testing.expect(!notifySyscallRequest());
        cpu_count = MAX_CPUS;
        @atomicStore(bool, &cpus[0].online, false, .release);
        try std.testing.expect(!notifySyscallRequest());
        @atomicStore(bool, &cpus[0].online, true, .release);
        @atomicStore(bool, &cpus[cpu].online, false, .release);
        try std.testing.expect(!notifySyscallRequest());
        @atomicStore(bool, &cpus[cpu].online, true, .release);
        try std.testing.expect(!notifySyscallCompletion(cpu));
        try std.testing.expect(notifySyscallRequest());
        try std.testing.expectEqual(x2apic.icrValue(.{
            .destination = cpus[0].apic_id,
            .vector = SYSCALL_REQUEST_IPI_VECTOR,
        }), Trace.values[Trace.count - 1]);
        cpu_identity.setIndexForTest(0);
        @atomicStore(bool, &cpus[cpu].online, false, .release);
        try std.testing.expect(!notifySyscallCompletion(cpu));
        @atomicStore(bool, &cpus[cpu].online, true, .release);
        try std.testing.expect(notifySyscallCompletion(cpu));
        try std.testing.expectEqual(x2apic.icrValue(.{
            .destination = cpus[cpu].apic_id,
            .vector = SYSCALL_COMPLETION_IPI_VECTOR,
        }), Trace.values[Trace.count - 1]);
    }
    try std.testing.expectEqual(@as(usize, 2 * (MAX_CPUS - 1)), Trace.count);
    try std.testing.expect(!Trace.invalid_msr);
}
