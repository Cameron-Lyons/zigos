const x86 = @import("../../arch/x86.zig");
const vga = @import("../drivers/vga.zig");
const console = @import("../utils/console.zig");
const config = @import("../config.zig");
const common = @import("common.zig");
const init_core = @import("init/core.zig");
const init_devices = @import("init/devices.zig");
const init_network = @import("init/network.zig");
const init_filesystems = @import("init/filesystems.zig");
const init_runtime = @import("init/runtime.zig");
const dev_profile = @import("profiles/dev.zig");
const ci_smoke_profile = @import("profiles/ci_smoke.zig");
const test_vm_profile = @import("profiles/test_vm.zig");
const vm_core_regression_profile = @import("profiles/vm_core_regression.zig");
const vm_readiness_regression_profile = @import("profiles/vm_readiness_regression.zig");
const vm_memory_regression_profile = @import("profiles/vm_memory_regression.zig");
const vm_state_regression_profile = @import("profiles/vm_state_regression.zig");
const vm_tty_regression_profile = @import("profiles/vm_tty_regression.zig");
const vm_socket_regression_profile = @import("profiles/vm_socket_regression.zig");
const vm_event_regression_profile = @import("profiles/vm_event_regression.zig");
const vm_inotify_regression_profile = @import("profiles/vm_inotify_regression.zig");
const benchmark_profile = @import("profiles/benchmark.zig");
const smp_stress_profile = @import("profiles/smp_stress.zig");
const smp_regression_profile = @import("profiles/smp_regression.zig");
const manual_regression_profile = @import("profiles/manual_regression.zig");
const ext2_regression_profile = @import("profiles/ext2_regression.zig");
const service_regression_profile = @import("profiles/service_regression.zig");
const scheduler_regression_profile = @import("profiles/scheduler_regression.zig");
const nic_ingress_profile = @import("profiles/nic_ingress.zig");
const e1000_ingress_profile = @import("profiles/e1000_ingress.zig");
const virtio_ingress_profile = @import("profiles/virtio_ingress.zig");
const userland_smoke_profile = @import("profiles/userland_smoke.zig");
const userland_sh_smoke_profile = @import("profiles/userland_sh_smoke.zig");

pub fn kernelMain() void {
    x86.enableSse();
    vga.init();
    vga.clear();
    console.init();
    common.printBootMarker("BOOT:START");
    common.printBootProfile();
    console.print("Welcome to ZigOS!\n");
    console.print("A minimal operating system written in Zig\n");

    init_core.init();
    init_devices.init();
    if (config.shouldInitNetworkStack()) {
        init_network.init();
    }
    init_filesystems.init();
    init_runtime.init();

    common.printBootMarker("BOOT:CORE_READY");

    switch (config.bootProfile()) {
        .dev => dev_profile.run(),
        .ci_smoke => ci_smoke_profile.run(),
        .test_vm => test_vm_profile.run(),
        .vm_core_regression => vm_core_regression_profile.run(),
        .vm_readiness_regression => vm_readiness_regression_profile.run(),
        .vm_memory_regression => vm_memory_regression_profile.run(),
        .vm_state_regression => vm_state_regression_profile.run(),
        .vm_tty_regression => vm_tty_regression_profile.run(),
        .vm_socket_regression => vm_socket_regression_profile.run(),
        .vm_event_regression => vm_event_regression_profile.run(),
        .vm_inotify_regression => vm_inotify_regression_profile.run(),
        .benchmark => benchmark_profile.run(),
        .smp_stress => smp_stress_profile.run(),
        .smp_regression => smp_regression_profile.run(),
        .manual_regression => manual_regression_profile.run(),
        .ext2_regression => ext2_regression_profile.run(),
        .service_regression => service_regression_profile.run(),
        .scheduler_regression => scheduler_regression_profile.run(),
        .nic_ingress => nic_ingress_profile.run(),
        .e1000_ingress => e1000_ingress_profile.run(),
        .virtio_ingress => virtio_ingress_profile.run(),
        .userland_smoke => userland_smoke_profile.run(),
        .userland_sh_smoke => userland_sh_smoke_profile.run(),
    }
}
