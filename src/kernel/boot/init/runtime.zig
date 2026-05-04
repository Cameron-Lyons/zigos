const console = @import("../../utils/console.zig");
const timer = @import("../../timer/timer.zig");
const keyboard = @import("../../drivers/keyboard.zig");
const devices = @import("devices.zig");

pub fn init() void {
    console.print("Initializing timer...\n");
    timer.init(timer.DEFAULT_FREQUENCY_HZ);

    console.print("Recording keyboard bootstrap inventory...\n");
    keyboard.recordBootstrapInventoryOnly();
    console.print("Keyboard data plane deferred to userspace driver contracts.\n");

    devices.startDeferredRuntimeInit();
}
