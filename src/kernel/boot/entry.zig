const x86 = @import("../../arch/x86.zig");
const cpu_features = @import("../../arch/cpu_features.zig");
const console = @import("../utils/console.zig");
const config = @import("../config.zig");
const common = @import("common.zig");
const boot_markers = @import("markers.zig");
const init_core = @import("init/core.zig");
const init_devices = @import("init/devices.zig");
const init_runtime = @import("init/runtime.zig");
const hardware_proof = @import("../platform/hardware_proof.zig");

pub fn kernelMain() void {
    x86.enableSse();
    console.init();
    common.printBootMarker(boot_markers.boot_start);
    common.printBootProfile();
    const hardening = cpu_features.detect();
    cpu_features.enable(hardening);
    common.printBootMarker(if (hardening.smep) boot_markers.cpu_smep_enabled else boot_markers.cpu_smep_absent);
    common.printBootMarker(if (hardening.umip) boot_markers.cpu_umip_enabled else boot_markers.cpu_umip_absent);
    console.print("Welcome to Zigos!\n");
    console.print("A minimal operating system written in Zig\n");
    hardware_proof.captureEarlyBootEvidence();

    init_core.init();
    init_devices.init();
    console.print("Delegating network ownership to native service contracts.\n");
    common.printBootMarker(boot_markers.kernel_network_deferred);
    init_runtime.init();

    common.printBootMarker(boot_markers.boot_core_ready);
    switch (config.bootProfile()) {
        .zigos_native => @import("profiles/zigos_native.zig").run(),
        .recovery => @import("profiles/recovery.zig").run(),
        .benchmark => @import("profiles/benchmark.zig").run(),
    }
}
