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
const tsc_clock = @import("../timer/tsc_clock.zig");

const QEMU_TSC_FREQUENCY_HZ: u64 = 2_400_000_000;

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
    if (cpu_features.baseline.firstMissing(features)) |missing_feature| {
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
    cpu_features.enableModernFeatures(features);
    common.printBootMarker(boot_markers.cpu_nx_enabled);
    common.printBootMarker(boot_markers.cpu_smep_enabled);
    common.printBootMarker(boot_markers.cpu_smap_enabled);
    common.printBootMarker(boot_markers.cpu_umip_enabled);
    common.printBootMarker(boot_markers.cpu_pge_enabled);
    common.printBootMarker(boot_markers.cpu_pcid_enabled);
    common.printBootMarker(boot_markers.cpu_pcid_ready);
    common.printBootMarker(boot_markers.cpu_pku_enabled);
    common.printBootMarker(boot_markers.cpu_lass_enabled);
    console.print("Welcome to Zigos!\n");
    console.print("A minimal operating system written in Zig\n");
    hardware_proof.captureEarlyBootEvidence();

    init_core.init();
    common.printBootMarker(boot_markers.cpu_fred_enabled);
    init_devices.init();
    console.print("Delegating device dataplanes to userspace driver claims.\n");
    common.printBootMarker(boot_markers.kernel_dataplane_userspace);
    common.printBootMarker(boot_markers.kernel_network_deferred);
    init_runtime.init(features, .tsc_deadline);
    @import("../smp.zig").init(hardware_proof.madtTable());

    common.printBootMarker(boot_markers.boot_core_ready);
    switch (comptime config.bootProfile()) {
        .zigos_native => @import("profiles/zigos_native.zig").run(),
        .recovery => @import("profiles/recovery.zig").run(),
        .benchmark => @import("profiles/benchmark.zig").run(),
    }
}
