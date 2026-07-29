const console = @import("../../utils/console.zig");
const cpu_baseline = @import("../../../arch/cpu_baseline.zig");
const timer = @import("../../timer/timer.zig");
const devices = @import("devices.zig");

pub fn init(features: cpu_baseline.Features, timer_mode: timer.Mode) void {
    console.print("Initializing timer...\n");
    timer.init(features, timer_mode);

    devices.startDeferredRuntimeInit();
}
