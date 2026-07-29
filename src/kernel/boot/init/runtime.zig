const console = @import("../../utils/console.zig");
const timer = @import("../../timer/timer.zig");
const devices = @import("devices.zig");

pub fn init() void {
    console.print("Initializing timer...\n");
    timer.init(timer.DEFAULT_FREQUENCY_HZ);

    devices.startDeferredRuntimeInit();
}
