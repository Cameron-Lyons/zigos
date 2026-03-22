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
const benchmark_profile = @import("profiles/benchmark.zig");
const smp_stress_profile = @import("profiles/smp_stress.zig");
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
        .benchmark => benchmark_profile.run(),
        .smp_stress => smp_stress_profile.run(),
        .userland_smoke => userland_smoke_profile.run(),
        .userland_sh_smoke => userland_sh_smoke_profile.run(),
    }
}
