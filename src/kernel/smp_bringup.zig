const smp = @import("smp.zig");
const x2apic = @import("interrupts/x2apic.zig");
const x86 = @import("../arch/x86.zig");
const cpu_features = @import("../arch/cpu_features.zig");
const cpu_policy = @import("boot/cpu_policy.zig");
const cpu_identity = @import("cpu_identity.zig");
const console = @import("utils/console.zig");
const tsc_clock = @import("timer/tsc_clock.zig");
const timer = @import("timer/timer.zig");
const spin = @import("utils/spin.zig");
const paging = @import("memory/paging64.zig");
const gdt = @import("interrupts/gdt64.zig");
const idt = @import("interrupts/idt64.zig");
const trampoline_bridge = @import("smp/trampoline.zig");

const INIT_HOLD_MILLISECONDS: u64 = 10;
const STARTUP_HOLD_MILLISECONDS: u64 = 1;
const AP_ONLINE_MILLISECONDS: u64 = 100;

var bringup_cpus: *[smp.MAX_CPUS]smp.Cpu = undefined;
var bringup_cpu_count: *u8 = undefined;
var bringup_online_count: *u8 = undefined;
var startup_page_physical: u32 = 0;
// Published once by the BSP before INIT/SIPI and then only read by APs.
var admission_policy: cpu_policy.AdmissionPolicy = undefined;
var rejection_reasons: [smp.MAX_CPUS]u8 = @splat(0);
const ADDRESS_PARTITION_REJECTED: u8 = 255;
const TIMER_ADMISSION_REJECTED: u8 = 254;

pub fn start(cpus: *[smp.MAX_CPUS]smp.Cpu, cpu_count: *u8, online_count: *u8, policy: cpu_policy.AdmissionPolicy) void {
    bringup_cpus = cpus;
    bringup_cpu_count = cpu_count;
    bringup_online_count = online_count;
    admission_policy = policy;
    paging.setRemotePcidShootdown(smp.shootdownPcid);
    paging.setRemoteKernelShootdown(smp.shootdownKernel);
    paging.setDeviceAliasTransition(smp.beginDeviceAliasTransition, smp.flushDeviceAliasTransition, smp.endDeviceAliasTransition);
    if (cpu_count.* <= 1) return;
    const trampoline = trampoline_bridge.install() orelse return;
    if (!paging.kernelAddressSpaceActive()) @panic("AP startup requires the kernel address space");
    // Only the AP transition executes this lower-half page, with LASS off.
    // The BSP continues accessing its backing through the supervisor alias.
    paging.mapKernelBorrowedPage(
        trampoline.physical,
        trampoline.physical,
        paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_EXECUTABLE,
    );
    startup_page_physical = trampoline.physical;
    defer {
        if (!paging.unmapBorrowedCurrentPage(trampoline.physical))
            @panic("failed to retire the AP startup mapping");
        startup_page_physical = 0;
    }
    var index: u8 = 1;
    while (index < cpu_count.*) : (index += 1) {
        startOne(index, trampoline);
    }
}

fn startOne(index: u8, trampoline: trampoline_bridge.Trampoline) void {
    const stack = trampoline_bridge.allocateStack() orelse return;
    const stack_top = stack.top;
    bringup_cpus[index].kernel_stack_top = stack_top;
    if (!trampoline_bridge.patch(trampoline, index, stack_top, &apEntry))
        @panic("invalid AP trampoline patch");

    const apic_id = bringup_cpus[index].apic_id;
    const vector: u8 = @intCast(trampoline.physical / 4096);
    x2apic.sendInit(apic_id);
    waitMilliseconds(INIT_HOLD_MILLISECONDS);
    x2apic.sendStartup(apic_id, vector);
    waitMilliseconds(STARTUP_HOLD_MILLISECONDS);
    if (!cpuOnline(index)) {
        x2apic.sendStartup(apic_id, vector);
        waitMilliseconds(STARTUP_HOLD_MILLISECONDS);
    }

    const deadline = tsc_clock.afterMilliseconds(AP_ONLINE_MILLISECONDS);
    while (!cpuOnline(index)) {
        const rejection = @atomicLoad(u8, &rejection_reasons[index], .acquire);
        if (rejection != 0 or deadline.expired()) {
            // Quiesce a late AP before patching the shared bridge for another
            // CPU or retiring its identity mapping on the runtime owner.
            x2apic.sendInit(apic_id);
            waitMilliseconds(INIT_HOLD_MILLISECONDS);
            @atomicStore(bool, &bringup_cpus[index].online, false, .release);
            if (rejection != 0) {
                console.print("AP CPU policy rejected: ");
                if (rejection == ADDRESS_PARTITION_REJECTED) {
                    console.print("noncanonical kernel address partition");
                } else if (rejection == TIMER_ADMISSION_REJECTED) {
                    console.print("timer clock authority mismatch");
                } else if (cpu_features.cache_policy.rejectionName(rejection)) |name| {
                    console.print(name);
                } else {
                    const missing: cpu_features.baseline.MissingFeature = @fromBackingInt(@intCast(rejection - 1));
                    console.print(@tagName(missing));
                }
                console.print("\n");
            }
            return;
        }
        spin.hint();
    }
    // Only the BSP counts admitted CPUs. A reset between AP initialization and
    // its release publication cannot leak an increment for an offline CPU.
    _ = @atomicRmw(u8, bringup_online_count, .Add, 1, .acq_rel);
}

fn cpuOnline(index: u8) bool {
    return @atomicLoad(bool, &bringup_cpus[index].online, .acquire);
}

fn waitMilliseconds(milliseconds: u64) void {
    const deadline = tsc_clock.afterMilliseconds(milliseconds);
    while (!deadline.expired()) spin.hint();
}

fn apEntry(cpu_index: u64) callconv(.c) noreturn {
    const index = @import("std").math.cast(u8, cpu_index) orelse park();
    if (index == 0 or index >= bringup_cpu_count.* or index >= smp.MAX_CPUS) park();
    // The assembly gate establishes only the compiler ISA and minimal FP
    // controls. Every AP must pass the BSP's immutable CPU and clock policy
    // before identity, privileged feature activation or online publication.
    const detected_features = cpu_features.detect();
    if (admission_policy.firstMissing(detected_features)) |missing| {
        @atomicStore(u8, &rejection_reasons[index], @backingInt(missing) + 1, .release);
        park();
    }
    const features = admission_policy.resolveFeatures(detected_features);
    // INIT preserves firmware cache policy. Reject a legal but different AP
    // MTRR map before native feature activation or online publication. The
    // assembly bridge already admitted this CPU's full PAT and CD/NW before PG.
    cpu_features.admitApplicationProcessorCache() catch |err| {
        @atomicStore(u8, &rejection_reasons[index], cpu_features.cache_policy.rejectionCode(err), .release);
        park();
    };
    // Descriptor and allocator selection must never observe firmware TSC_AUX.
    cpu_identity.initialize(index);
    paging.initializeCurrentKernelRoot();
    // The AP has permanently left the bridge. Drop its cached global low leaf
    // before acknowledging startup; the BSP removes the shared page-table leaf
    // and invalidates its own translation after every AP has left or reset.
    x86.invalidatePage(startup_page_physical);
    gdt.initCpu(index);
    gdt.setKernelStack(bringup_cpus[index].kernel_stack_top);
    cpu_features.enableModernFeatures(
        features,
        admission_policy.process_context_mode,
        admission_policy.cet_mode,
        admission_policy.featureMode(),
    );
    const syscall64 = @import("interrupts/syscall64.zig");
    syscall64.initApplicationProcessor(index, bringup_cpus[index].kernel_stack_top);
    // Interrupt stubs require the published GS state and owned xstate, even
    // for an NMI while ordinary interrupts remain disabled.
    idt.init();
    // LASS also checks implicit GDT, IDT and TSS accesses. Admit it only after
    // the processor owns high descriptor tables and its high FRED stacks.
    if (features.lass) {
        x86.enableLass() catch {
            @atomicStore(u8, &rejection_reasons[index], ADDRESS_PARTITION_REJECTED, .release);
            park();
        };
    }
    x2apic.enable();
    // Adopt the immutable BSP clock without resetting its epoch or another
    // CPU's timer. Every admitted AP starts with its local wake source disarmed.
    if (!timer.initApplicationProcessor(features)) {
        @atomicStore(u8, &rejection_reasons[index], TIMER_ADMISSION_REJECTED, .release);
        park();
    }
    @atomicStore(bool, &bringup_cpus[index].online, true, .release);
    while (true) smp.idle();
}

fn park() noreturn {
    x86.cli();
    while (true) x86.hlt();
}
