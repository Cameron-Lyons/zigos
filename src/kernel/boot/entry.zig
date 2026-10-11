const std = @import("std");
const secure_random = @import("../platform/secure_random.zig");
const x86 = @import("../../arch/x86.zig");
const cpu_features = @import("../../arch/cpu_features.zig");
const cpu_policy = @import("cpu_policy.zig");
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

comptime {
    if (!tcb.FORBIDS_PRODUCT_IMPORTS or !tcb.KERNEL_PORT_REQUIRES_PUBLISHED_GS or !tcb.IDLE_NEVER_SERVICES_DEVICE_QUEUES) {
        @compileError("kernel TCB contracts must stay enabled");
    }
}

fn cpuModelRequest() cpu_policy.ModelRequest {
    const info = handoff.capturedInfo() orelse return .{};
    return .{
        .model_inventory = handoff.commandLineHasFlag(info, "model_inventory"),
        .software_cpu_fallback = handoff.commandLineHasFlag(info, "qemu_software_cpu_fallback"),
        .tsc_frequency_hz = handoff.commandLineU64(info, "qemu_tsc_frequency_hz"),
    };
}

fn printBootIdentity() void {
    common.printBootMarker(boot_markers.boot_start);
    common.printBootProfile();
    common.printKernelRole();
}

pub fn kernelMain() void {
    // Native assembly has already established FP controls before compiled code.
    console.init();
    const detected_features = cpu_features.detect();
    const model_request = cpuModelRequest();
    const admission_policy = cpu_policy.AdmissionPolicy.init(detected_features, model_request);
    const features = admission_policy.resolveFeatures(detected_features);
    const hardware_process_contexts = admission_policy.process_context_mode == .hardware_pcid;
    const hardware_tsc_timer = admission_policy.hardware_tsc_timer;
    const hardware_pku = features.pku;
    const hardware_lass = admission_policy.hardware_lass;
    const hardware_fred = admission_policy.hardware_fred;
    if (admission_policy.firstMissing(detected_features)) |missing_feature| {
        printBootIdentity();
        common.printBootMarker(boot_markers.cpu_baseline_rejected);
        console.print("Unsupported CPU: missing ");
        console.print(@tagName(missing_feature));
        console.print("\n");
        x86.cli();
        while (true) x86.hlt();
    }
    cpu_features.initializeNativeCachePolicy() catch |err| {
        printBootIdentity();
        console.print("Unsupported memory cache policy: ");
        console.print(@errorName(err));
        console.print("\n");
        x86.cli();
        while (true) x86.hlt();
    };
    tsc_clock.init(features.tsc_frequency_hz);
    printBootIdentity();
    common.printBootMarker(boot_markers.cpu_baseline_ready);
    secure_random.initialize(features.rdseed) catch |err| {
        common.printBootMarker(boot_markers.random_rejected);
        console.print(@errorName(err));
        console.print("\n");
        x86.cli();
        while (true) x86.hlt();
    };
    common.printBootMarker(boot_markers.random_ready);
    console.print("ZIGOS:BOOT:INSTANCE ");
    const instance_hex = std.fmt.bytesToHex(&secure_random.bootInstanceId(), .lower);
    console.print(&instance_hex);
    console.print("\n");
    cpu_features.enableModernFeatures(
        features,
        admission_policy.process_context_mode,
        admission_policy.cet_mode,
        admission_policy.featureMode(),
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
    console.print("Welcome to Zigos!\n");
    console.print("A minimal operating system written in Zig\n");
    hardware_proof.captureEarlyBootEvidence();

    init_core.init(hardware_lass) catch {
        common.printBootMarker(boot_markers.cpu_lass_address_partition_rejected);
        console.print("Unsupported kernel address partition: LASS requires canonical upper-half instruction, stack, kernel data and descriptor table addresses\n");
        x86.cli();
        while (true) x86.hlt();
    };
    if (hardware_lass) {
        common.printBootMarker(boot_markers.cpu_lass_enabled);
    }
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
    @import("../smp.zig").init(hardware_proof.madtTable(), admission_policy);

    common.printBootMarker(boot_markers.boot_core_ready);
    switch (comptime config.bootProfile()) {
        .zigos_native => @import("profiles/zigos_native.zig").run(),
        .recovery => @import("profiles/recovery.zig").run(),
        .benchmark => @import("profiles/benchmark.zig").run(),
    }
}
