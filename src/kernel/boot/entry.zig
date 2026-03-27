const x86 = @import("../../arch/x86.zig");
const vga = @import("../drivers/vga.zig");
const console = @import("../utils/console.zig");
const config = @import("../config.zig");
const common = @import("common.zig");
const init_core = @import("init/core.zig");
const init_devices = @import("init/devices.zig");
const init_runtime = @import("init/runtime.zig");

pub fn kernelMain() void {
    x86.enableSse();
    vga.init();
    vga.clear();
    console.init();
    common.printBootMarker("BOOT:START");
    common.printBootProfile();
    console.print("Welcome to Zigos!\n");
    console.print("A minimal operating system written in Zig\n");

    init_core.init();
    init_devices.init();
    console.print("Delegating network ownership to native service contracts.\n");
    common.printBootMarker("ZIGOS:PHASE3:KERNEL_NETWORK:DEFERRED");
    init_runtime.init();

    common.printBootMarker("BOOT:CORE_READY");
    @import("profiles/zigos_native.zig").run();
}
