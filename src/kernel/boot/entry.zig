const x86 = @import("../../arch/x86.zig");
const cpu_features = @import("../../arch/cpu_features.zig");
const vga = @import("../drivers/vga.zig");
const console = @import("../utils/console.zig");
const config = @import("../config.zig");
const common = @import("common.zig");
const boot_markers = @import("markers.zig");
const init_core = @import("init/core.zig");
const init_devices = @import("init/devices.zig");
const init_runtime = @import("init/runtime.zig");
const hardware_proof = @import("../platform/hardware_proof.zig");

pub fn kernelMain() void {
    // The long-mode Zig entry may use SSE registers before CPUID decoding.
    // SSE2 is therefore both an entry precondition and an explicitly verified
    // member of the supported CPU contract.
    x86.enableSse();
    vga.init();
    vga.clear();
    console.init();
    common.printBootMarker(boot_markers.boot_start);
    common.printBootProfile();
    common.printKernelRole();
    const features = cpu_features.detect();
    if (!cpu_features.baseline.isSupported(features)) {
        common.printBootMarker(boot_markers.cpu_baseline_rejected);
        console.print("Unsupported CPU: modern x86-64 feature baseline required\n");
        x86.cli();
        while (true) x86.hlt();
    }
    common.printBootMarker(boot_markers.cpu_baseline_ready);
    cpu_features.enableSupervisorProtections(features);
    common.printBootMarker(boot_markers.cpu_nx_enabled);
    common.printBootMarker(boot_markers.cpu_smep_enabled);
    common.printBootMarker(boot_markers.cpu_umip_enabled);
    console.print("Welcome to Zigos!\n");
    console.print("A minimal operating system written in Zig\n");
    hardware_proof.captureEarlyBootEvidence();

    init_core.init();
    init_devices.init();
    console.print("Delegating network ownership to native service contracts.\n");
    common.printBootMarker(boot_markers.kernel_network_deferred);
    init_runtime.init();

    common.printBootMarker(boot_markers.boot_core_ready);
    switch (comptime config.bootProfile()) {
        .zigos_native => @import("profiles/zigos_native.zig").run(),
        .recovery => @import("profiles/recovery.zig").run(),
        .benchmark => @import("profiles/benchmark.zig").run(),
    }
}
