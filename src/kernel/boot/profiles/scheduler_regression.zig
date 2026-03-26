const console = @import("../../utils/console.zig");
const process = @import("../../process/process.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const common = @import("../common.zig");
const multitask_demo = @import("../../tests/multitask_demo.zig");
const procmon = @import("../../tests/procmon.zig");

fn fail(marker: []const u8) noreturn {
    common.printBootMarker(marker);
    common.printBootMarker("SCHEDREG:FAIL");
    qemu_exit.failure();
}

pub fn run() noreturn {
    const runner = process.create_kernel_process("scheduler_regression_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);

    console.print("Running scheduler regression suites...\n");
    common.printBootMarker("SCHEDREG:START");

    common.printBootMarker("SCHEDREG:DEMO:START");
    if (!multitask_demo.runSchedulerDemoChecked()) {
        fail("SCHEDREG:DEMO:FAIL");
    }
    common.printBootMarker("SCHEDREG:DEMO:PASS");

    common.printBootMarker("SCHEDREG:PROCMON:START");
    if (!procmon.runMonitoringChecksChecked()) {
        fail("SCHEDREG:PROCMON:FAIL");
    }
    common.printBootMarker("SCHEDREG:PROCMON:PASS");

    common.printBootMarker("SCHEDREG:PASS");
    qemu_exit.success();
}
