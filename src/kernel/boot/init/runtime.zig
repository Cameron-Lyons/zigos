const console = @import("../../utils/console.zig");
const config = @import("../../config.zig");
const credentials = @import("../../process/credentials.zig");
const process = @import("../../process/process.zig");
const smp = @import("../../smp/smp.zig");
const ata = @import("../../drivers/ata.zig");
const network = @import("../../net/network.zig");
const timer = @import("../../timer/timer.zig");
const keyboard = @import("../../drivers/keyboard.zig");
const common = @import("../common.zig");
const devices = @import("devices.zig");

pub fn init() void {
    console.print("Initializing credentials...\n");
    credentials.init();

    console.print("Initializing process management...\n");
    process.init();

    if (config.shouldInitSmp()) {
        smp.startSecondaryCPUs();
        if (smp.isSMPEnabled()) {
            console.print("SMP enabled with ");
            common.printCpuCount(smp.getActiveCPUCount());
            console.print(" CPUs\n");
        } else if (smp.getNumCPUs() > 1) {
            console.print("SMP startup unavailable, continuing on BSP only\n");
        }
    }

    if (config.shouldInitRuntimeExtras()) {
        console.print("Starting async IO workers...\n");
        ata.startAsyncWorker();
        network.startWorkers();

        console.print("Initializing process monitoring...\n");
        const procmon = @import("../../tests/procmon.zig");
        procmon.init();
    }

    console.print("Initializing timer...\n");
    timer.init(timer.DEFAULT_FREQUENCY_HZ);

    console.print("Initializing keyboard...\n");
    keyboard.init();
    console.print("Keyboard ready!\n");

    devices.startDeferredRuntimeInit();
}
