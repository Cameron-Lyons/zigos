const x86 = @import("../../arch/x86.zig");
const cpu_features = @import("../../arch/cpu_features.zig");
const console = @import("../utils/console.zig");
const config = @import("../config.zig");
const common = @import("common.zig");
const handoff = @import("handoff.zig");
const boot_markers = @import("markers.zig");
const init_core = @import("init/core.zig");
const init_devices = @import("init/devices.zig");
const init_runtime = @import("init/runtime.zig");
const hardware_proof = @import("../platform/hardware_proof.zig");
const tcb = @import("../tcb.zig");
const tsc_clock = @import("../timer/tsc_clock.zig");

const QEMU_TSC_FREQUENCY_HZ: u64 = 2_400_000_000;

comptime {
    if (!tcb.FORBIDS_PRODUCT_IMPORTS or !tcb.KERNEL_PORT_REQUIRES_PUBLISHED_GS or !tcb.IDLE_NEVER_SERVICES_DEVICE_QUEUES) {
        @compileError("kernel TCB contracts must stay enabled");
    }
}

fn softwareCpuFallbackRequested() bool {
    const info = handoff.capturedInfo() orelse return false;
    return handoff.commandLineHasFlag(info, "model_inventory") and
        handoff.commandLineHasFlag(info, "qemu_software_cpu_fallback") and
        handoff.commandLineU64(info, "qemu_tsc_frequency_hz") == QEMU_TSC_FREQUENCY_HZ;
}

fn printBootIdentity() void {
    common.printBootMarker(boot_markers.boot_start);
    common.printBootProfile();
    common.printKernelRole();
}

pub fn kernelMain() void {
    x86.enableSse();
    console.init();
    var features = cpu_features.detect();
    if (features.tsc_frequency_hz == 0) {
        if (handoff.capturedInfo()) |info| {
            if (handoff.commandLineHasFlag(info, "model_inventory") and
                handoff.commandLineU64(info, "qemu_tsc_frequency_hz") == QEMU_TSC_FREQUENCY_HZ)
            {
                features.tsc_frequency_hz = QEMU_TSC_FREQUENCY_HZ;
            }
        }
    }
    const software_cpu_fallback = softwareCpuFallbackRequested();
    const hardware_process_contexts = features.pcid and features.invpcid;
    const software_process_context_fallback = !hardware_process_contexts and software_cpu_fallback;
    const hardware_tsc_timer = features.tsc_deadline and features.invariant_tsc;
    const software_timer_fallback = !hardware_tsc_timer and software_cpu_fallback;
    const hardware_cet = features.cet_ibt and features.cet_ss;
    const software_cet_fallback = !hardware_cet and software_cpu_fallback;
    const hardware_pku = features.pku;
    const hardware_lass = features.lass;
    const software_lass_fallback = !hardware_lass and software_cpu_fallback;
    const hardware_fred = features.fred and features.lkgs;
    const qemu_inventory_boot = software_cpu_fallback;
    var required_features = features;
    if (software_process_context_fallback) {
        required_features.pcid = true;
        required_features.invpcid = true;
    }
    if (software_timer_fallback) {
        required_features.tsc_deadline = true;
        required_features.invariant_tsc = true;
    }
    if (software_cet_fallback) {
        required_features.cet_ibt = true;
        required_features.cet_ss = true;
    }
    if (software_lass_fallback) {
        required_features.lass = true;
    }
    if (qemu_inventory_boot and !hardware_fred) {
        required_features.fred = true;
        required_features.lkgs = true;
    }
    if (cpu_features.baseline.firstMissing(required_features)) |missing_feature| {
        printBootIdentity();
        common.printBootMarker(boot_markers.cpu_baseline_rejected);
        console.print("Unsupported CPU: missing ");
        console.print(@tagName(missing_feature));
        console.print("\n");
        x86.cli();
        while (true) x86.hlt();
    }
    tsc_clock.init(features.tsc_frequency_hz);
    printBootIdentity();
    common.printBootMarker(boot_markers.cpu_baseline_ready);
    cpu_features.enableModernFeatures(
        features,
        if (hardware_process_contexts) .hardware_pcid else .software_flush,
        if (hardware_cet) .hardware else .deferred,
    );
    common.printBootMarker(boot_markers.cpu_nx_enabled);
    common.printBootMarker(boot_markers.cpu_smep_enabled);
    common.printBootMarker(boot_markers.cpu_smap_enabled);
    common.printBootMarker(boot_markers.cpu_umip_enabled);
    common.printBootMarker(boot_markers.cpu_pge_enabled);
    if (hardware_process_contexts) {
        common.printBootMarker(boot_markers.cpu_pcid_enabled);
    } else {
        common.printBootMarker(boot_markers.cpu_pcid_software_fallback);
    }
    common.printBootMarker(boot_markers.cpu_pcid_ready);
    if (hardware_pku) {
        common.printBootMarker(boot_markers.cpu_pku_enabled);
    }
    if (hardware_lass) {
        common.printBootMarker(boot_markers.cpu_lass_enabled);
    }
    console.print("Welcome to Zigos!\n");
    console.print("A minimal operating system written in Zig\n");
    hardware_proof.captureEarlyBootEvidence();

    init_core.init();
    if (hardware_fred) {
        common.printBootMarker(boot_markers.cpu_fred_enabled);
    } else {
        common.printBootMarker(boot_markers.cpu_syscall_enabled);
    }
    init_devices.init();
    console.print("Delegating device dataplanes to userspace driver claims.\n");
    common.printBootMarker(boot_markers.kernel_dataplane_userspace);
    common.printBootMarker(boot_markers.kernel_network_deferred);
    init_runtime.init(
        features,
        if (hardware_tsc_timer) .tsc_deadline else .calibrated_countdown,
    );
    @import("../smp.zig").init(hardware_proof.madtTable());

    common.printBootMarker(boot_markers.boot_core_ready);
    switch (comptime config.bootProfile()) {
        .zigos_native => @import("profiles/zigos_native.zig").run(),
        .recovery => @import("profiles/recovery.zig").run(),
        .benchmark => @import("profiles/benchmark.zig").run(),
    }
}
