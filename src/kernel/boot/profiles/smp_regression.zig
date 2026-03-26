const console = @import("../../utils/console.zig");
const process = @import("../../process/process.zig");
const qemu_exit = @import("../../utils/qemu_exit.zig");
const smp = @import("../../smp/smp.zig");
const common = @import("../common.zig");
const test_smp = @import("../../tests/test_smp.zig");

fn fail(marker: []const u8) noreturn {
    common.printBootMarker(marker);
    common.printBootMarker("SMPREG:FAIL");
    qemu_exit.failure();
}

pub fn run() noreturn {
    const runner = process.create_kernel_process("smp_regression_runner", common.idleTaskPlaceholder);
    process.adoptAsCurrent(runner);

    console.print("Running SMP regression suite...\n");
    common.printBootMarker("SMPREG:START");
    console.print("SMPREG:ACTIVE_CPUS:");
    common.printCpuCount(smp.getActiveCPUCount());
    console.print("\n");

    if (!test_smp.runSMPTestsChecked()) {
        fail("SMPREG:SUITE:FAIL");
    }

    common.printBootMarker("SMPREG:PASS");
    qemu_exit.success();
}
