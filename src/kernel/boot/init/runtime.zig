const console = @import("../../utils/console.zig");
const timer = @import("../../timer/timer.zig");
const keyboard = @import("../../drivers/keyboard.zig");
const devices = @import("devices.zig");

pub fn init() void {
    console.print("Initializing timer...\n");
    timer.init(timer.DEFAULT_FREQUENCY_HZ);

    console.print("Deferring keyboard input data plane to userspace driver contracts...\n");
    keyboard.deferInputDataPlaneToUserspace();

    devices.startDeferredRuntimeInit();
}
